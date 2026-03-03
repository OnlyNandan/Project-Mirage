"""
Project Mirage — Diversion Detection Engine

Two detection modes:
  1. Individual flight diversion  — a flight destined for a UAE airport leaves the box
  2. Airspace emptying            — total flight count drops significantly from baseline
"""

import logging
from collections import deque

from datetime import datetime, timezone, timedelta

from config import (
    HEADING_CHANGE_THRESHOLD_DEG,
    BASELINE_WINDOW,
    FLIGHT_COUNT_DROP_PERCENT,
    CRITICAL_MIN_FLIGHTS,
    UAE_AIRPORTS_IATA,
    UAE_AIRPORTS_ICAO,
    STARTUP_GRACE_POLLS,
    QUIET_HOURS,
    QUIET_HOUR_DROP_PERCENT,
)

UAE_TZ = timezone(timedelta(hours=4))
from tracker import Tracker, FlightTrack
from alerter import Alerter, Alert, Severity

logger = logging.getLogger("mirage.detector")

# Emergency squawk codes
SQUAWK_EMERGENCY = {"7500", "7600", "7700"}


class Detector:
    """Analyzes tracker data each poll cycle and fires alerts."""

    def __init__(self, tracker: Tracker, alerter: Alerter):
        self.tracker = tracker
        self.alerter = alerter
        self._count_history: deque[int] = deque(maxlen=BASELINE_WINDOW)
        self._baseline: float | None = None

    # ── Main entry point (called each poll cycle) ────────────────────────────

    def analyze(self, new_tracks: list[FlightTrack], exited_tracks: list[FlightTrack]):
        """Run all detection checks for the current poll cycle."""

        current_count = self.tracker.active_count
        self._count_history.append(current_count)

        # Update rolling baseline
        if len(self._count_history) >= 3:
            self._baseline = sum(self._count_history) / len(self._count_history)

        # Skip detection during startup grace period
        if self.tracker.poll_count <= STARTUP_GRACE_POLLS:
            logger.info(
                f"Grace period poll {self.tracker.poll_count}/{STARTUP_GRACE_POLLS} "
                f"— {current_count} flights, building baseline..."
            )
            return

        # ── Check 1: individual diversions ───────────────────────────────
        for track in exited_tracks:
            self._check_individual_diversion(track)

        # ── Check 2: heading anomalies on active flights ─────────────────
        for fid, track in self.tracker.active_tracks.items():
            self._check_heading_change(track)
            self._check_squawk(track)

        # ── Check 3: airspace emptying ───────────────────────────────────
        self._check_airspace_emptying(current_count)

        # Housekeeping
        self.alerter.cleanup_cooldowns()

    # ── Individual Diversion Detection ───────────────────────────────────────

    def _check_individual_diversion(self, track: FlightTrack):
        """Check if a flight that left the box was expected or a diversion."""
        last = track.last
        if not last:
            return

        dest = last.destination.upper().strip()
        dest_is_uae = dest in UAE_AIRPORTS_IATA or dest in UAE_AIRPORTS_ICAO

        if dest_is_uae:
            # Flight was heading TO a UAE airport but left airspace — DIVERSION
            self.alerter.send(Alert(
                severity=Severity.WARNING,
                title=f"Flight Diverted: {last.callsign or track.flight_id}",
                message=(
                    f"{last.callsign} ({last.aircraft_code}) was heading to {dest} "
                    f"but left UAE airspace. "
                    f"Last pos: {last.latitude:.3f}°N, {last.longitude:.3f}°E, "
                    f"HDG {last.heading:.0f}°, FL{last.altitude / 100:.0f}"
                ),
                flight_id=track.flight_id,
            ))
        elif dest == "" or dest == "N/A":
            # Unknown destination — flag as suspicious
            self.alerter.send(Alert(
                severity=Severity.WARNING,
                title=f"Unknown flight left: {last.callsign or track.flight_id}",
                message=(
                    f"{last.callsign} ({last.aircraft_code}) left UAE airspace "
                    f"with unknown destination. "
                    f"Last pos: {last.latitude:.3f}°N, {last.longitude:.3f}°E, "
                    f"HDG {last.heading:.0f}°"
                ),
                flight_id=track.flight_id,
            ))
        else:
            # Destination is outside UAE — expected exit, no alert
            logger.debug(
                f"Expected exit: {last.callsign} → {dest} (non-UAE destination)"
            )

    # ── Heading Change Detection ─────────────────────────────────────────────

    def _check_heading_change(self, track: FlightTrack):
        """Detect sharp heading changes that might indicate a diversion in progress."""
        if not track.is_mature:
            return

        last = track.last
        prev = track.prev
        if not last or not prev:
            return

        delta = abs(last.heading - prev.heading)
        # Normalize to 0–180 range (shortest arc)
        if delta > 180:
            delta = 360 - delta

        if delta >= HEADING_CHANGE_THRESHOLD_DEG:
            # Check if the flight is at low speed (likely holding pattern) — skip
            if last.ground_speed < 150:
                logger.debug(
                    f"Heading change {delta:.0f}° for {last.callsign} ignored (low speed, likely holding)"
                )
                return

            self.alerter.send(Alert(
                severity=Severity.WARNING,
                title=f"Sharp turn: {last.callsign or track.flight_id}",
                message=(
                    f"{last.callsign} changed heading by {delta:.0f}° "
                    f"({prev.heading:.0f}° → {last.heading:.0f}°) "
                    f"at FL{last.altitude / 100:.0f}, {last.ground_speed:.0f}kt. "
                    f"Possible diversion in progress."
                ),
                flight_id=track.flight_id,
            ))

    # ── Squawk Code Detection ────────────────────────────────────────────────

    def _check_squawk(self, track: FlightTrack):
        """Check for emergency squawk codes."""
        last = track.last
        if not last or not last.squawk:
            return

        if last.squawk in SQUAWK_EMERGENCY:
            labels = {
                "7500": "HIJACK",
                "7600": "RADIO FAILURE",
                "7700": "EMERGENCY",
            }
            label = labels.get(last.squawk, "EMERGENCY")
            self.alerter.send(Alert(
                severity=Severity.CRITICAL,
                title=f"SQUAWK {last.squawk} — {label}: {last.callsign}",
                message=(
                    f"{last.callsign} ({last.aircraft_code}) is squawking {last.squawk} ({label})! "
                    f"Pos: {last.latitude:.3f}°N, {last.longitude:.3f}°E, "
                    f"FL{last.altitude / 100:.0f}, HDG {last.heading:.0f}°"
                ),
                flight_id=track.flight_id,
            ))

    # ── Airspace Emptying Detection ──────────────────────────────────────────

    @staticmethod
    def _is_quiet_hours() -> bool:
        """Check if it's currently quiet hours in UAE."""
        uae_hour = datetime.now(UAE_TZ).hour
        start, end = QUIET_HOURS
        return start <= uae_hour < end

    def _check_airspace_emptying(self, current_count: int):
        """Detect if the airspace is emptying out (mass diversion/avoidance)."""
        is_quiet = self._is_quiet_hours()

        # Critical: almost no flights at all
        if current_count <= CRITICAL_MIN_FLIGHTS:
            self.alerter.send(Alert(
                severity=Severity.CRITICAL,
                title="AIRSPACE NEARLY EMPTY",
                message=(
                    f"Only {current_count} flights in UAE airspace! "
                    f"This is critically low. Possible mass diversion or airspace closure."
                    + (" (Note: quiet hours in UAE)" if is_quiet else "")
                ),
                flight_id="__airspace_empty__",
            ))
            return

        # Percentage drop from baseline
        if self._baseline and self._baseline > 0:
            drop_pct = ((self._baseline - current_count) / self._baseline) * 100
            threshold = QUIET_HOUR_DROP_PERCENT if is_quiet else FLIGHT_COUNT_DROP_PERCENT

            if drop_pct >= threshold:
                self.alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title="AIRSPACE FLIGHT COUNT DROPPING",
                    message=(
                        f"Flight count dropped {drop_pct:.1f}% from baseline "
                        f"({self._baseline:.0f} → {current_count}). "
                        f"Possible mass diversion or airspace avoidance."
                        + (" (Note: quiet hours in UAE)" if is_quiet else "")
                    ),
                    flight_id="__airspace_drop__",
                ))

    # ── Status Reporting ─────────────────────────────────────────────────────

    @property
    def baseline(self) -> float | None:
        return self._baseline

    @property
    def status_summary(self) -> str:
        baseline_str = f"{self._baseline:.0f}" if self._baseline else "calculating..."
        return (
            f"Active: {self.tracker.active_count} | "
            f"Baseline: {baseline_str} | "
            f"Tracked total: {self.tracker.total_tracked} | "
            f"Alerts: {len(self.alerter.history)}"
        )
