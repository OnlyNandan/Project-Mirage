#!/usr/bin/env python3
"""
Project Mirage — UAE Airspace Monitor
Main entry point. Polls FlightRadar24 for commercial flights in the UAE
bounding box and alerts on diversions or airspace emptying.

Usage:
    python main.py              # Normal mode
    python main.py --verbose    # Debug logging
    python main.py --interval 10  # Custom poll interval (seconds)
    python main.py --test-alert # Send a test notification and exit
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timezone, timedelta

from FlightRadar24.api import FlightRadar24API

from config import (
    UAE_BOUNDS_STR,
    POLL_INTERVAL_SEC,
    BANNER,
    STARTUP_GRACE_POLLS,
)
from tracker import Tracker
from detector import Detector
from alerter import Alerter, Alert, Severity

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
    _running = False

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─── Main Loop ───────────────────────────────────────────────────────────────

def run(interval: int = POLL_INTERVAL_SEC, verbose: bool = False):
    """Main monitoring loop."""
    global _running

    print(BANNER)
    setup_logging(verbose)

    # Initialize components
    fr = FlightRadar24API()
    tracker = Tracker()
    alerter = Alerter()
    detector = Detector(tracker, alerter)

    print(f"  Monitoring UAE airspace (bounds: {UAE_BOUNDS_STR})")
    print(f"  Poll interval: {interval}s")
    print(f"  Grace period: {STARTUP_GRACE_POLLS} polls before active detection")
    print(f"  Press Ctrl+C to stop\n")
    print("─" * 60)

    consecutive_errors = 0
    max_consecutive_errors = 5

    while _running:
        cycle_start = time.time()

        try:
            # ── Fetch flights from FR24 ──────────────────────────────────
            raw_flights = fr.get_flights(bounds=UAE_BOUNDS_STR)
            consecutive_errors = 0  # Reset on success

            # ── Update tracker ───────────────────────────────────────────
            new_tracks, exited_tracks = tracker.update(raw_flights)

            # ── Run detection ────────────────────────────────────────────
            detector.analyze(new_tracks, exited_tracks)

            # ── Print status line ────────────────────────────────────────
            now = datetime.now(UAE_TZ).strftime("%H:%M:%S")
            status = detector.status_summary

            # Color code the flight count
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
                f"  [{now} UAE] {count_color}✈ {count}\033[0m flights"
                f"{new_str}{exit_str} │ {status}"
            )

        except KeyboardInterrupt:
            break
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Poll error ({consecutive_errors}/{max_consecutive_errors}): {e}")

            if consecutive_errors >= max_consecutive_errors:
                alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title="MONITOR FAILURE",
                    message=f"FR24 API failed {max_consecutive_errors} times in a row: {e}",
                    flight_id="__system__",
                ))
                print(f"\n\033[91m  ✖ Too many consecutive errors. Check your connection.\033[0m")
                # Don't break — keep retrying but with backoff
                time.sleep(min(interval * consecutive_errors, 120))
                continue

        # ── Sleep until next cycle ───────────────────────────────────────
        elapsed = time.time() - cycle_start
        sleep_time = max(0, interval - elapsed)
        if _running and sleep_time > 0:
            time.sleep(sleep_time)

    # ── Shutdown ─────────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print(f"  Session summary:")
    print(f"    Polls completed: {tracker.poll_count}")
    print(f"    Flights tracked: {tracker.total_tracked}")
    print(f"    Alerts fired:    {len(alerter.history)}")
    print("─" * 60)
    print("  Goodbye. ✈️\n")


# ─── Test Alert ──────────────────────────────────────────────────────────────

def test_alert():
    """Send a test macOS notification to verify alerts work."""
    print(BANNER)
    alerter = Alerter()
    print("  Sending test notifications...\n")

    alerter.send(Alert(
        severity=Severity.INFO,
        title="Test: Info",
        message="Project Mirage notifications are working!",
    ))
    time.sleep(1)

    alerter.send(Alert(
        severity=Severity.WARNING,
        title="Test: Diversion",
        message="EK203 diverted from DXB — this is a test alert.",
        flight_id="test_flight",
    ))
    time.sleep(1)

    alerter.send(Alert(
        severity=Severity.CRITICAL,
        title="Test: Airspace Empty",
        message="UAE airspace critical — only 3 flights! (Test)",
        flight_id="test_critical",
    ))

    print("\n  ✓ Check your macOS Notification Center for 3 test alerts.")
    print("  If you don't see them, check System Settings → Notifications → Script Editor.\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Project Mirage — UAE Airspace Diversion Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Start monitoring
  python main.py --verbose          Debug mode
  python main.py --interval 10      Poll every 10 seconds
  python main.py --test-alert       Test notification delivery
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
        help="Send test notifications and exit",
    )

    args = parser.parse_args()

    if args.test_alert:
        test_alert()
    else:
        run(interval=args.interval, verbose=args.verbose)


if __name__ == "__main__":
    main()
