#!/usr/bin/env python3
"""
Project Mirage — UAE Threat Monitor
FlightRadar24 approach-abort detection with ML feedback learning.

The core idea: track planes approaching DXB — if they turn around
instead of landing, it's likely a missile/attack. SIREN fires.
After 5 minutes, the system asks "was there a boom?" so the model learns.

Usage:
    python main.py              # Normal mode
    python main.py --verbose    # Debug logging
    python main.py --interval 15  # Custom poll interval (seconds)
    python main.py --test-alert # Send test notifications (with sounds) and exit
    python main.py --no-sound   # Disable sound alerts
"""

import argparse
import logging
import signal
import sys
import time
import select
from datetime import datetime, timezone, timedelta

from FlightRadar24.api import FlightRadar24API

from config import (
    UAE_BOUNDS_STR,
    POLL_INTERVAL_SEC,
    BANNER,
    STARTUP_GRACE_POLLS,
    FEEDBACK_DELAY_SEC,
)
from tracker import Tracker
from detector import Detector
from alerter import Alerter, Alert, Severity
from approach_model import ApproachAbortModel
from sounds import ensure_sounds, stop_all

# ─── Logging Setup ───────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s │ %(name)-18s │ %(levelname)-7s │ %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


logger = logging.getLogger("mirage.main")

# ── UAE timezone for display ────────────────────────────────────────────────
UAE_TZ = timezone(timedelta(hours=4))


# ─── Graceful Shutdown ───────────────────────────────────────────────────────

_running = True

def _signal_handler(sig, frame):
    global _running
    print("\n\033[93m⏹  Shutting down gracefully...\033[0m")
    stop_all()
    _running = False

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─── Feedback Prompter ──────────────────────────────────────────────────────

def _ask_feedback_nonblocking(model: ApproachAbortModel):
    """
    Check if any abort events need user feedback (5 min after siren).
    Uses non-blocking stdin check so it doesn't interrupt monitoring.
    """
    pending = model.get_pending_feedback()
    if not pending:
        return

    for event in pending:
        age_min = (time.time() - event.timestamp) / 60
        print(f"\n\033[95m{'━' * 60}")
        print(f"  🔔 FEEDBACK NEEDED ({age_min:.0f} min ago)")
        print(f"  {event.callsign} aborted approach to {event.airport}")
        print(f"  Score: {event.score:.1f} | Distance: {event.abort_distance_nm:.0f}nm")
        print(f"  Was there a boom/attack? [y/n/s(kip)]: ", end="", flush=True)
        print(f"\033[0m", end="", flush=True)

        # Non-blocking read with 30-second timeout
        answer = _read_with_timeout(30)

        if answer is None:
            print("\n  (no response — will ask again next cycle)")
            continue

        answer = answer.strip().lower()
        if answer in ("y", "yes"):
            model.submit_feedback(event, was_attack=True)
            print(f"\033[91m  ✓ Marked as CONFIRMED ATTACK — model weights updated\033[0m")
        elif answer in ("n", "no"):
            model.submit_feedback(event, was_attack=False)
            print(f"\033[92m  ✓ Marked as FALSE POSITIVE — model weights updated\033[0m")
        elif answer in ("s", "skip"):
            model.dismiss_pending(event)
            print(f"  ✓ Skipped (treated as false positive)")
        else:
            print(f"  ✓ Unrecognized '{answer}' — skipping for now")


def _read_with_timeout(timeout_sec: int) -> str | None:
    """Read a line from stdin with a timeout. Returns None if no input."""
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout_sec)
        if ready:
            return sys.stdin.readline()
    except (ValueError, OSError):
        pass
    return None


# ─── Main Loop ───────────────────────────────────────────────────────────────

def run(interval: int = POLL_INTERVAL_SEC, verbose: bool = False, sound: bool = True):
    """Main monitoring loop — runs until Ctrl+C."""
    global _running

    # Override sound setting
    if not sound:
        import config
        config.ALERT_SOUND = False

    print(BANNER)
    setup_logging(verbose)

    # Initialize components
    fr = FlightRadar24API()
    tracker = Tracker()
    alerter = Alerter()
    model = ApproachAbortModel()
    detector = Detector(tracker, alerter, model)

    # Generate sound files upfront
    if sound:
        ensure_sounds()

    print(f"  Source: FlightRadar24")
    print(f"  Monitoring UAE airspace (bounds: {UAE_BOUNDS_STR})")
    print(f"  Poll interval: {interval}s")
    print(f"  Sound: {'ON — siren on approach-abort / ping on warnings' if sound else 'OFF'}")
    print(f"  Grace period: {STARTUP_GRACE_POLLS} polls before detection activates")
    print(f"  Detection: approach-abort (ML) + holding + GPS spoofing + airspace")
    print(f"  Feedback: system asks you after {FEEDBACK_DELAY_SEC//60}min — was there a boom?")
    print(f"  Model: {model.stats}")
    print(f"  Press Ctrl+C to stop\n")
    print("─" * 60)

    consecutive_fr24_errors = 0
    max_consecutive_errors = 5

    while _running:
        cycle_start = time.time()
        now_str = datetime.now(UAE_TZ).strftime("%H:%M:%S")

        # ═══════════════════════════════════════════════════════════════
        # PART 1: FlightRadar24 Airspace + Approach-Abort Detection
        # ═══════════════════════════════════════════════════════════════
        try:
            raw_flights = fr.get_flights(bounds=UAE_BOUNDS_STR)
            consecutive_fr24_errors = 0

            new_tracks, exited_tracks = tracker.update(raw_flights)
            detector.analyze(new_tracks, exited_tracks)

            # Status line
            count = tracker.active_count
            if count == 0:
                count_color = "\033[91m"  # Red
            elif detector.abort_count > 0:
                count_color = "\033[91m"  # Red — aborts happening!
            elif detector.baseline and count < detector.baseline * 0.8:
                count_color = "\033[93m"  # Yellow
            else:
                count_color = "\033[92m"  # Green

            new_str = f" +{len(new_tracks)}" if new_tracks else ""
            exit_str = f" -{len(exited_tracks)}" if exited_tracks else ""

            print(
                f"  [{now_str} UAE] {count_color}✈ {count}\033[0m flights"
                f"{new_str}{exit_str} │ {detector.status_summary}"
            )

        except KeyboardInterrupt:
            break
        except Exception as e:
            consecutive_fr24_errors += 1
            logger.error(f"FR24 error ({consecutive_fr24_errors}/{max_consecutive_errors}): {e}")
            print(f"  [{now_str} UAE] \033[91m✈ FR24 ERROR\033[0m ({consecutive_fr24_errors}x)")

            if consecutive_fr24_errors >= max_consecutive_errors:
                alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title="FR24 MONITOR FAILURE",
                    message=f"FR24 API failed {max_consecutive_errors}x in a row: {e}",
                    flight_id="__system_fr24__",
                    source="system",
                ))

        # ═══════════════════════════════════════════════════════════════
        # PART 2: Check for pending user feedback (was there a boom?)
        # ═══════════════════════════════════════════════════════════════
        _ask_feedback_nonblocking(model)

        # ═══════════════════════════════════════════════════════════════
        # Sleep until next cycle
        # ═══════════════════════════════════════════════════════════════
        elapsed = time.time() - cycle_start
        sleep_time = max(0, interval - elapsed)
        if _running and sleep_time > 0:
            time.sleep(sleep_time)

    # ── Shutdown ─────────────────────────────────────────────────────────────
    alerter.shutdown()
    print("\n" + "─" * 60)
    print(f"  Session summary:")
    print(f"    Polls completed: {tracker.poll_count}")
    print(f"    Flights tracked: {tracker.total_tracked}")
    print(f"    Alerts fired:    {len(alerter.history)}")
    print(f"    Model:           {model.stats}")
    print("─" * 60)
    print("  Goodbye. ✈️\n")


# ─── Test Alert ──────────────────────────────────────────────────────────────

def test_alert():
    """Send test notifications with full sound to verify setup."""
    print(BANNER)
    alerter = Alerter()
    print("  Sending test notifications with sound...\n")

    alerter.send(Alert(
        severity=Severity.INFO,
        title="Test: Info Ping",
        message="Project Mirage notifications + sounds are working!",
    ))
    time.sleep(2)

    alerter.send(Alert(
        severity=Severity.WARNING,
        title="Test: Warning Ping",
        message="EK203 heading change detected — this is a test warning.",
        flight_id="test_flight",
    ))
    time.sleep(2)

    alerter.send(Alert(
        severity=Severity.CRITICAL,
        title="Test: APPROACH ABORT SIREN",
        message="EK203 aborted approach to DXB — SIREN TEST",
        flight_id="test_critical",
    ))

    # Wait for siren to finish playing
    time.sleep(8)
    alerter.shutdown()

    print("\n  ✓ You should have heard:")
    print("    - 2x ping sounds (INFO + WARNING)")
    print("    - 1x siren sound (CRITICAL — approach abort)")
    print("  If no sound, check System Settings → Sound → Alert volume.\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Project Mirage — UAE Threat Monitor (FlightRadar24 Approach-Abort ML)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Start monitoring (runs until Ctrl+C)
  python main.py --verbose          Debug mode
  python main.py --interval 10      Poll every 10 seconds
  python main.py --no-sound         Disable sound alerts
  python main.py --test-alert       Test notifications + sound
        """,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=POLL_INTERVAL_SEC,
        help=f"Poll interval in seconds (default: {POLL_INTERVAL_SEC})",
    )
    parser.add_argument(
        "--test-alert",
        action="store_true",
        help="Send test notifications with sound and exit",
    )
    parser.add_argument(
        "--no-sound",
        action="store_true",
        help="Disable sound alerts (siren/ping)",
    )

    args = parser.parse_args()

    if args.test_alert:
        test_alert()
    else:
        run(interval=args.interval, verbose=args.verbose, sound=not args.no_sound)


if __name__ == "__main__":
    main()
