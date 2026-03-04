#!/usr/bin/env python3
"""
Project Mirage — UAE Threat Monitor
Unified monitoring: FlightRadar24 airspace + OSINT (Google News, Reddit).

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
import threading
from datetime import datetime, timezone, timedelta

from FlightRadar24.api import FlightRadar24API

from config import (
    UAE_BOUNDS_STR,
    POLL_INTERVAL_SEC,
    BANNER,
    STARTUP_GRACE_POLLS,
    OSINT_GOOGLE_NEWS_ENABLED,
    OSINT_REDDIT_ENABLED,
)
from tracker import Tracker
from detector import Detector
from alerter import Alerter, Alert, Severity
from osint import OSINTMonitor
from sounds import ensure_sounds, stop_all

# ─── Logging Setup ───────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s │ %(name)-18s │ %(levelname)-7s │ %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    # Silence noisy urllib3
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
    detector = Detector(tracker, alerter)
    osint = OSINTMonitor()

    # Generate sound files upfront
    if sound:
        ensure_sounds()

    sources = []
    if True:  # FR24 always on
        sources.append("FlightRadar24")
    if OSINT_GOOGLE_NEWS_ENABLED:
        sources.append("Google News")
    if OSINT_REDDIT_ENABLED:
        sources.append("Reddit")

    print(f"  Sources: {' + '.join(sources)}")
    print(f"  Monitoring UAE airspace (bounds: {UAE_BOUNDS_STR})")
    print(f"  Poll interval: {interval}s")
    print(f"  Sound alerts: {'ON — siren (flights only) / ping (warnings)' if sound else 'OFF'}")
    print(f"  Grace period: {STARTUP_GRACE_POLLS} polls before flight detection activates")
    print(f"  Detection: diversions, holding patterns, GPS spoofing, airspace emptying")
    print(f"  OSINT: news/social monitoring (ping only, no siren)")
    print(f"  Press Ctrl+C to stop\n")
    print("─" * 60)

    consecutive_fr24_errors = 0
    max_consecutive_errors = 5

    # OSINT runs in a background thread so it never blocks FR24 polling
    osint_results: list = []       # Shared list for thread results
    osint_lock = threading.Lock()
    osint_new_count = 0            # New items from last completed OSINT poll

    def _osint_worker():
        """Background worker: polls OSINT sources and deposits results."""
        nonlocal osint_new_count
        while _running:
            try:
                items = osint.poll()
                with osint_lock:
                    osint_results.extend(items)
                    osint_new_count = len(items)
            except Exception as e:
                logger.warning(f"OSINT poll error: {e}")
            # OSINT polls on same interval, offset slightly
            for _ in range(interval):
                if not _running:
                    break
                time.sleep(1)

    osint_thread = threading.Thread(target=_osint_worker, daemon=True, name="osint")
    osint_thread.start()

    while _running:
        cycle_start = time.time()
        now_str = datetime.now(UAE_TZ).strftime("%H:%M:%S")

        # ═══════════════════════════════════════════════════════════════
        # PART 1: FlightRadar24 Airspace Monitoring
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
            elif detector.baseline and count < detector.baseline * 0.8:
                count_color = "\033[93m"  # Yellow
            else:
                count_color = "\033[92m"  # Green

            new_str = f" +{len(new_tracks)}" if new_tracks else ""
            exit_str = f" -{len(exited_tracks)}" if exited_tracks else ""

            print(
                f"  [{now_str} UAE] {count_color}✈ {count}\033[0m flights"
                f"{new_str}{exit_str} │ {detector.status_summary}",
                end=""
            )

        except KeyboardInterrupt:
            break
        except Exception as e:
            consecutive_fr24_errors += 1
            logger.error(f"FR24 error ({consecutive_fr24_errors}/{max_consecutive_errors}): {e}")
            print(f"  [{now_str} UAE] \033[91m✈ FR24 ERROR\033[0m", end="")

            if consecutive_fr24_errors >= max_consecutive_errors:
                alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title="FR24 MONITOR FAILURE",
                    message=f"FR24 API failed {max_consecutive_errors}x in a row: {e}",
                    flight_id="__system_fr24__",
                    source="system",
                ))

        # ═══════════════════════════════════════════════════════════════
        # PART 2: Process OSINT results (from background thread)
        # ═══════════════════════════════════════════════════════════════
        with osint_lock:
            pending_items = list(osint_results)
            osint_results.clear()
            new_osint = osint_new_count

        for item in pending_items:
            # OSINT never triggers siren — cap at WARNING (ping only)
            severity = Severity.WARNING
            alerter.send(Alert(
                severity=severity,
                title=f"OSINT [{item.source}]: {', '.join(item.matched_keywords[:3])}",
                message=f"{item.title[:120]}\n{item.url}",
                flight_id=item.dedup_key,
                source="osint",
            ))

        # Print OSINT status on same line
        osint_str = f" │ \033[96m📡 OSINT: {osint.total_items} hits\033[0m"
        if new_osint > 0:
            osint_str += f" (+{new_osint} new!)"
        print(osint_str)

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
    print(f"    OSINT items:     {osint.total_items}")
    print(f"    Alerts fired:    {len(alerter.history)}")
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
        message="EK203 diverted from DXB — this is a test warning (ping sound).",
        flight_id="test_flight",
    ))
    time.sleep(2)

    alerter.send(Alert(
        severity=Severity.CRITICAL,
        title="Test: CRITICAL SIREN",
        message="UAE airspace critical — SIREN SOUND TEST",
        flight_id="test_critical",
    ))

    # Wait for siren to finish playing
    time.sleep(8)
    alerter.shutdown()

    print("\n  ✓ You should have heard:")
    print("    - 2x ping sounds (INFO + WARNING)")
    print("    - 1x siren sound (CRITICAL)")
    print("  Check macOS Notification Center for 3 test alerts.")
    print("  If no sound, check System Settings → Sound → Alert volume.\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Project Mirage — UAE Threat Monitor (FlightRadar24 + OSINT)",
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
