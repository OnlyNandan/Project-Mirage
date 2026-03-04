"""
Project Mirage — Diversion Detection Engine

Detection modes:
  1. Individual flight diversion  — a flight destined for a UAE airport leaves the box
  2. Holding pattern detection    — flight circling near airport (cumulative heading > 360°)
  3. GPS spoofing detection       — impossible jumps, heading/movement mismatch, position clusters
  4. Airspace emptying            — total flight count drops significantly from baseline
  5. Emergency squawk codes       — 7500/7600/7700
"""

import math
import logging
from collections import deque, defaultdict

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
    HOLDING_CUMULATIVE_DEG,
    HOLDING_MIN_SNAPSHOTS,
    HOLDING_MAX_ALTITUDE_FT,
    HOLDING_MAX_DISTANCE_NM,
    SPOOF_MAX_SPEED_KT,
    SPOOF_HEADING_MISMATCH_DEG,
    SPOOF_CLUSTER_RADIUS_DEG,
    SPOOF_CLUSTER_MIN_FLIGHTS,
)

UAE_TZ = timezone(timedelta(hours=4))
from tracker import Tracker, FlightTrack, FlightSnapshot
from alerter import Alerter, Alert, Severity

logger = logging.getLogger("mirage.detector")

# Emergency squawk codes
SQUAWK_EMERGENCY = {"7500", "7600", "7700"}

# Major UAE airport positions (lat, lon) for holding pattern proximity checks
UAE_AIRPORT_POSITIONS = {
    "DXB": (25.2532, 55.3657),
    "AUH": (24.4330, 54.6511),
    "SHJ": (25.3286, 55.5172),
    "DWC": (24.8967, 55.1614),
    "RKT": (25.6135, 55.9388),
    "AAN": (24.2617, 55.6092),
    "FJR": (25.1122, 56.3240),
}


def _haversine_nm(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in nautical miles between two lat/lon points."""
    R_NM = 3440.065  # Earth radius in nautical miles
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return 2 * R_NM * math.asin(math.sqrt(a))


def _bearing_between(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate bearing (degrees) from point 1 to point 2."""
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlon = math.radians(lon2 - lon1)
    x = math.sin(dlon) * math.cos(rlat2)
    y = math.cos(rlat1) * math.sin(rlat2) - math.sin(rlat1) * math.cos(rlat2) * math.cos(dlon)
    return math.degrees(math.atan2(x, y)) % 360


class Detector:
    """Analyzes tracker data each poll cycle and fires alerts."""

    def __init__(self, tracker: Tracker, alerter: Alerter):
        self.tracker = tracker
        self.alerter = alerter
        self._count_history: deque[int] = deque(maxlen=BASELINE_WINDOW)
        self._baseline: float | None = None
        self._holding_alerted: set[str] = set()  # flight IDs already alerted for holding
        self._spoof_alerted: set[str] = set()    # flight IDs already alerted for spoofing
        self.holding_count: int = 0               # current count of flights in holding
        self.spoof_count: int = 0                 # current count of spoofing anomalies
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

        # ── Check 2: heading anomalies + squawk + holding + spoofing ─────
        holding_this_cycle = 0
        spoof_this_cycle = 0

        for fid, track in self.tracker.active_tracks.items():
            self._check_heading_change(track)
            self._check_squawk(track)
            if self._check_holding_pattern(track):
                holding_this_cycle += 1
            if self._check_gps_spoofing(track):
                spoof_this_cycle += 1

        self.holding_count = holding_this_cycle
        self.spoof_count = spoof_this_cycle

        # ── Check 3: GPS spoofing — position clustering ──────────────────
        self._check_position_clustering()

        # ── Check 4: airspace emptying ───────────────────────────────────
        self._check_airspace_emptying(current_count)

        # ── Check 5: mass holding pattern = CRITICAL ─────────────────────
        if holding_this_cycle >= 3:
            self.alerter.send(Alert(
                severity=Severity.CRITICAL,
                title="MULTIPLE FLIGHTS HOLDING",
                message=(
                    f"{holding_this_cycle} flights are in holding patterns near UAE airports! "
                    f"Possible airspace threat or closure in progress."
                ),
                flight_id="__mass_holding__",
            ))

        # Housekeeping
        self.alerter.cleanup_cooldowns()
        self._cleanup_detection_state()

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

    # ── Holding Pattern Detection ────────────────────────────────────────────

    def _check_holding_pattern(self, track: FlightTrack) -> bool:
        """
        Detect if a flight is in a holding pattern (circling).
        
        During attacks (like yesterday's 9:00 incident), flights destined for DXB/UAE
        enter holds — they circle repeatedly instead of landing. We detect this by
        measuring cumulative heading change over recent snapshots. A full circle = 360°.
        
        Returns True if flight is in a holding pattern.
        """
        if not track.is_mature:
            return False
        
        snaps = track.snapshots
        if len(snaps) < HOLDING_MIN_SNAPSHOTS:
            return False
        
        last = snaps[-1]
        
        # Only check flights at reasonable holding altitude
        if last.altitude > HOLDING_MAX_ALTITUDE_FT or last.altitude < 3000:
            return False
        
        # Must be near a UAE airport
        nearest_airport, dist = self._nearest_uae_airport(last.latitude, last.longitude)
        if dist > HOLDING_MAX_DISTANCE_NM:
            return False
        
        # Calculate cumulative heading change over last N snapshots
        recent = snaps[-HOLDING_MIN_SNAPSHOTS:]
        cumulative = 0.0
        for i in range(1, len(recent)):
            delta = recent[i].heading - recent[i - 1].heading
            # Normalize to -180..+180 (signed, preserves turn direction)
            if delta > 180:
                delta -= 360
            elif delta < -180:
                delta += 360
            cumulative += delta
        
        abs_cumulative = abs(cumulative)
        
        if abs_cumulative >= HOLDING_CUMULATIVE_DEG:
            fid = track.flight_id
            direction = "clockwise" if cumulative > 0 else "counter-clockwise"
            
            if fid not in self._holding_alerted:
                self._holding_alerted.add(fid)
                self.alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title=f"HOLDING PATTERN: {last.callsign or fid}",
                    message=(
                        f"{last.callsign} is circling {direction} near {nearest_airport} "
                        f"({abs_cumulative:.0f}° rotation over {len(recent)} snapshots). "
                        f"Alt: FL{last.altitude / 100:.0f}, Dest: {last.destination}. "
                        f"Flight may be unable to land!"
                    ),
                    flight_id=fid,
                ))
            return True
        
        return False

    def _nearest_uae_airport(self, lat: float, lon: float) -> tuple[str, float]:
        """Find the nearest UAE airport and distance in NM."""
        best_name = "???"
        best_dist = float("inf")
        for name, (alat, alon) in UAE_AIRPORT_POSITIONS.items():
            d = _haversine_nm(lat, lon, alat, alon)
            if d < best_dist:
                best_dist = d
                best_name = name
        return best_name, best_dist

    # ── GPS Spoofing Detection ───────────────────────────────────────────────

    def _check_gps_spoofing(self, track: FlightTrack) -> bool:
        """
        Detect GPS spoofing anomalies on individual flights.
        
        GPS spoofing is active in the Middle East. Signs:
          1. Teleportation — position jumps faster than physically possible
          2. Heading/movement mismatch — reported heading doesn't match actual movement
        
        Returns True if spoofing indicators detected.
        """
        if len(track.snapshots) < 2:
            return False
        
        last = track.last
        prev = track.prev
        if not last or not prev:
            return False
        
        dt = last.timestamp - prev.timestamp
        if dt <= 0:
            return False
        
        spoofed = False
        fid = track.flight_id
        
        # Check 1: Impossible speed (teleportation)
        actual_dist_nm = _haversine_nm(prev.latitude, prev.longitude, 
                                        last.latitude, last.longitude)
        hours = dt / 3600.0
        if hours > 0:
            implied_speed = actual_dist_nm / hours
            if implied_speed > SPOOF_MAX_SPEED_KT and actual_dist_nm > 1.0:
                spoofed = True
                if fid not in self._spoof_alerted:
                    self._spoof_alerted.add(fid)
                    self.alerter.send(Alert(
                        severity=Severity.WARNING,
                        title=f"GPS SPOOF? Teleport: {last.callsign or fid}",
                        message=(
                            f"{last.callsign} jumped {actual_dist_nm:.1f}nm in {dt:.0f}s "
                            f"(implied {implied_speed:.0f}kt — impossible). "
                            f"Reported speed: {last.ground_speed:.0f}kt. GPS spoofing likely."
                        ),
                        flight_id=fid,
                        source="flight",
                    ))
        
        # Check 2: Heading vs actual movement vector mismatch
        if actual_dist_nm > 0.5 and last.ground_speed > 100:
            actual_bearing = _bearing_between(prev.latitude, prev.longitude,
                                               last.latitude, last.longitude)
            reported_heading = last.heading
            mismatch = abs(actual_bearing - reported_heading)
            if mismatch > 180:
                mismatch = 360 - mismatch
            
            if mismatch > SPOOF_HEADING_MISMATCH_DEG:
                spoofed = True
                if fid not in self._spoof_alerted:
                    self._spoof_alerted.add(fid)
                    self.alerter.send(Alert(
                        severity=Severity.WARNING,
                        title=f"GPS SPOOF? Heading mismatch: {last.callsign or fid}",
                        message=(
                            f"{last.callsign} reports HDG {reported_heading:.0f}° but "
                            f"actually moving {actual_bearing:.0f}° (Δ{mismatch:.0f}°). "
                            f"GPS spoofing indicators present."
                        ),
                        flight_id=fid,
                        source="flight",
                    ))
        
        return spoofed

    def _check_position_clustering(self):
        """
        Detect GPS spoofing via position clustering.
        
        When GPS is spoofed, multiple flights may report the same fake position.
        If 3+ flights are within ~1km of each other, flag it.
        """
        positions: list[tuple[str, str, float, float]] = []  # (fid, callsign, lat, lon)
        
        for fid, track in self.tracker.active_tracks.items():
            last = track.last
            if last:
                positions.append((fid, last.callsign, last.latitude, last.longitude))
        
        if len(positions) < SPOOF_CLUSTER_MIN_FLIGHTS:
            return
        
        # Simple O(n²) clustering — fine for ~50 flights
        clusters: dict[int, list[tuple[str, str]]] = defaultdict(list)
        visited = set()
        
        for i in range(len(positions)):
            if i in visited:
                continue
            cluster = [(positions[i][0], positions[i][1])]
            visited.add(i)
            
            for j in range(i + 1, len(positions)):
                if j in visited:
                    continue
                dlat = abs(positions[i][2] - positions[j][2])
                dlon = abs(positions[i][3] - positions[j][3])
                if dlat < SPOOF_CLUSTER_RADIUS_DEG and dlon < SPOOF_CLUSTER_RADIUS_DEG:
                    cluster.append((positions[j][0], positions[j][1]))
                    visited.add(j)
            
            if len(cluster) >= SPOOF_CLUSTER_MIN_FLIGHTS:
                callsigns = ", ".join(c[1] or c[0] for c in cluster[:5])
                self.alerter.send(Alert(
                    severity=Severity.WARNING,
                    title=f"GPS SPOOF? {len(cluster)} flights clustered",
                    message=(
                        f"{len(cluster)} flights at nearly identical position "
                        f"({positions[i][2]:.3f}°N, {positions[i][3]:.3f}°E): {callsigns}. "
                        f"GPS spoofing likely — multiple aircraft showing same fake position."
                    ),
                    flight_id="__spoof_cluster__",
                    source="flight",
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
        parts = [
            f"Active: {self.tracker.active_count}",
            f"Baseline: {baseline_str}",
            f"Tracked: {self.tracker.total_tracked}",
        ]
        if self.holding_count > 0:
            parts.append(f"\033[91m🔄 Holding: {self.holding_count}\033[0m")
        if self.spoof_count > 0:
            parts.append(f"\033[93m📡 Spoofed: {self.spoof_count}\033[0m")
        parts.append(f"Alerts: {len(self.alerter.history)}")
        return " | ".join(parts)

    # ── Housekeeping ─────────────────────────────────────────────────────────

    def _cleanup_detection_state(self):
        """Remove stale holding/spoof alert IDs for flights no longer tracked."""
        active_ids = set(self.tracker.active_tracks.keys())
        self._holding_alerted = self._holding_alerted & active_ids
        self._spoof_alerted = self._spoof_alerted & active_ids
