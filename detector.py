"""
Project Mirage — Diversion Detection Engine

Detection modes (priority order):
  1. APPROACH ABORT (primary) — plane on approach to DXB turns around → SIREN
     This is THE attack signal. Uses ML model with user feedback learning.
  2. Holding pattern detection  — flight circling near airport → SIREN
  3. GPS spoofing detection     — impossible jumps, heading/movement mismatch → WARNING
  4. Airspace emptying          — total flight count drops significantly → SIREN
  5. Emergency squawk codes     — 7500/7600/7700 → CRITICAL
  6. Individual flight diversion — UAE-destined flight leaves box → WARNING
"""

import math
import time
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
    APPROACH_MAX_DIST_NM,
    APPROACH_MIN_CLOSING_SNAPS,
    APPROACH_MIN_SPEED_KT,
    ABORT_HEADING_REVERSAL_DEG,
    ABORT_DIST_INCREASE_NM,
    ABORT_CONCURRENT_THRESHOLD,
    ABORT_WAVE_WINDOW_SEC,
    MASS_HOLDING_SIREN_THRESHOLD,
    MASS_HOLDING_WARN_THRESHOLD,
)

UAE_TZ = timezone(timedelta(hours=4))
from tracker import Tracker, FlightTrack, FlightSnapshot
from alerter import Alerter, Alert, Severity
from approach_model import ApproachAbortModel, AbortEvent

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

    def __init__(self, tracker: Tracker, alerter: Alerter, model: ApproachAbortModel | None = None):
        self.tracker = tracker
        self.alerter = alerter
        self.model = model or ApproachAbortModel()
        self._count_history: deque[int] = deque(maxlen=BASELINE_WINDOW)
        self._baseline: float | None = None
        self._holding_alerted: set[str] = set()  # flight IDs already alerted for holding
        self._spoof_alerted: set[str] = set()    # flight IDs already alerted for spoofing
        self._abort_alerted: set[str] = set()    # flight IDs already alerted for abort
        self._recent_aborts: list[tuple[float, str]] = []  # (timestamp, callsign) for wave detection
        self.holding_count: int = 0               # current count of flights in holding
        self.spoof_count: int = 0                 # current count of spoofing anomalies
        self.approach_count: int = 0              # flights currently on approach
        self.abort_count: int = 0                 # aborts detected this cycle
        self.abort_wave: bool = False             # True if an abort wave is active

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

        # ═══════════════════════════════════════════════════════════════
        # PRIMARY: Approach-Abort Detection
        # Single abort = WARNING (ping). Abort WAVE (2+ in 3min) = SIREN.
        # Abort + Holding together = SIREN (correlated signal — the real pattern).
        # ═══════════════════════════════════════════════════════════════
        abort_events = []
        approach_this_cycle = 0

        for fid, track in self.tracker.active_tracks.items():
            is_approaching = self._is_on_approach(track)
            if is_approaching:
                approach_this_cycle += 1
            abort = self._check_approach_abort(track)
            if abort:
                abort_events.append(abort)

        self.approach_count = approach_this_cycle

        # Also check exited flights — they may have aborted and LEFT the box
        for track in exited_tracks:
            abort = self._check_approach_abort(track)
            if abort:
                abort_events.append(abort)

        # Record new aborts into the wave tracker
        now = time.time()
        for abort_evt in abort_events:
            self._recent_aborts.append((now, abort_evt.callsign))

        # Prune old entries outside the wave window
        self._recent_aborts = [
            (t, cs) for t, cs in self._recent_aborts
            if now - t <= ABORT_WAVE_WINDOW_SEC
        ]

        wave_count = len(self._recent_aborts)

        # ── Holding patterns (run BEFORE abort alerting so we know count) ──
        holding_this_cycle = 0
        for fid, track in self.tracker.active_tracks.items():
            if self._check_holding_pattern(track):
                holding_this_cycle += 1
        self.holding_count = holding_this_cycle

        # ── Decide siren conditions ──
        # SIREN if: (a) 2+ aborts in wave window, OR
        #           (b) 1+ abort AND 1+ holding (the real attack pattern!), OR
        #           (c) mass holding alone (5+)
        is_wave = wave_count >= ABORT_CONCURRENT_THRESHOLD
        is_correlated = len(abort_events) >= 1 and holding_this_cycle >= 1
        should_siren = is_wave or is_correlated
        self.abort_wave = should_siren

        # Score and alert each abort event
        for abort_evt in abort_events:
            abort_evt.concurrent_aborts = wave_count
            abort_evt.time_since_last_true = self.model.time_since_last_confirmed
            score = self.model.score(abort_evt)

            if should_siren:
                abort_evt.triggered_siren = True
                if is_correlated and not is_wave:
                    reason = (
                        f"CORRELATED THREAT: {abort_evt.callsign} aborted approach "
                        f"while {holding_this_cycle} flight(s) circling (can't land). "
                    )
                else:
                    recent_callsigns = ", ".join(cs for _, cs in self._recent_aborts[-5:])
                    reason = (
                        f"ABORT WAVE: {wave_count} flights turned away in "
                        f"{ABORT_WAVE_WINDOW_SEC // 60}min: {recent_callsigns}. "
                    )
                self.alerter.send(Alert(
                    severity=Severity.CRITICAL,
                    title=f"🚀 THREAT DETECTED near {abort_evt.airport}",
                    message=(
                        f"{reason}"
                        f"Latest: {abort_evt.callsign} was {abort_evt.abort_distance_nm:.0f}nm "
                        f"from {abort_evt.airport}, turned Δ{abort_evt.heading_reversal_deg:.0f}°. "
                        f"{'Descending before abort. ' if abort_evt.was_descending else ''}"
                        f"Holding: {holding_this_cycle} | Score: {score:.1f}"
                    ),
                    flight_id="__threat_detected__",
                ))
            else:
                # Single abort, no holding — normal go-around. Just ping.
                abort_evt.triggered_siren = False
                self.alerter.send(Alert(
                    severity=Severity.WARNING,
                    title=f"Go-around: {abort_evt.callsign}",
                    message=(
                        f"{abort_evt.callsign} aborted approach to {abort_evt.airport} "
                        f"({abort_evt.abort_distance_nm:.0f}nm, Δ{abort_evt.heading_reversal_deg:.0f}°). "
                        f"Normal go-around unless more flights follow. Score: {score:.1f}"
                    ),
                    flight_id=abort_evt.flight_id,
                ))

            self.model.record_event(abort_evt)

        self.abort_count = len(abort_events)

        # ── Other checks (all WARNING or silent, never SIREN by themselves) ──

        # Check 1: individual diversions (non-abort exits)
        for track in exited_tracks:
            if track.flight_id not in self._abort_alerted:
                self._check_individual_diversion(track)

        # Check 2: squawk codes (only 7500/7700 = siren, 7600 = log only)
        for fid, track in self.tracker.active_tracks.items():
            self._check_squawk(track)

        # Check 3: heading changes (log only — too noisy for alerts)
        for fid, track in self.tracker.active_tracks.items():
            self._check_heading_change(track)

        # Check 4: mass holding thresholds (independent of abort)
        if holding_this_cycle >= MASS_HOLDING_SIREN_THRESHOLD:
            self.alerter.send(Alert(
                severity=Severity.CRITICAL,
                title=f"MASS HOLDING: {holding_this_cycle} flights circling!",
                message=(
                    f"{holding_this_cycle} flights in holding patterns near UAE airports. "
                    f"Airspace likely under threat or closure."
                ),
                flight_id="__mass_holding__",
            ))
        elif holding_this_cycle >= MASS_HOLDING_WARN_THRESHOLD and not should_siren:
            # Only ping for mass holding if we didn't already siren for correlated threat
            self.alerter.send(Alert(
                severity=Severity.WARNING,
                title=f"Multiple holdings: {holding_this_cycle} flights circling",
                message=(
                    f"{holding_this_cycle} flights holding near UAE airports. "
                    f"Could be weather or ATC. Watching for more."
                ),
                flight_id="__holding_warn__",
            ))

        # Check 5: GPS spoofing (always WARNING, never siren)
        spoof_this_cycle = 0
        for fid, track in self.tracker.active_tracks.items():
            if self._check_gps_spoofing(track):
                spoof_this_cycle += 1
        self.spoof_count = spoof_this_cycle
        self._check_position_clustering()

        # Check 6: airspace emptying (this CAN siren — flights disappearing is real)
        self._check_airspace_emptying(current_count)

        # Housekeeping
        self.alerter.cleanup_cooldowns()
        self._cleanup_detection_state()

    # ── Approach-Abort Detection (PRIMARY) ──────────────────────────────────

    def _is_on_approach(self, track: FlightTrack) -> bool:
        """
        Check if a flight is currently on approach to a UAE airport.
        
        On approach means:
          - Destination is a UAE airport
          - Within APPROACH_MAX_DIST_NM of that airport
          - Has been getting closer over recent snapshots (closing in)
          - At approach speed (> 150kt)
        """
        if len(track.snapshots) < 2:
            return False
        
        last = track.last
        if not last:
            return False
        
        # Must be at flight speed
        if last.ground_speed < APPROACH_MIN_SPEED_KT:
            return False
        
        # Must be heading to a UAE airport
        dest = last.destination.upper().strip()
        if dest not in UAE_AIRPORTS_IATA and dest not in UAE_AIRPORTS_ICAO:
            return False
        
        # Check distance to destination airport (or nearest UAE airport)
        airport_name, dist = self._nearest_uae_airport(last.latitude, last.longitude)
        if dist > APPROACH_MAX_DIST_NM:
            return False
        
        # Check if closing in (distance decreasing over recent snapshots)
        if len(track.snapshots) >= APPROACH_MIN_CLOSING_SNAPS:
            distances = []
            for snap in track.snapshots[-APPROACH_MIN_CLOSING_SNAPS:]:
                _, d = self._nearest_uae_airport(snap.latitude, snap.longitude)
                distances.append(d)
            
            # Most recent should be closer than oldest
            if distances[-1] < distances[0]:
                return True
        
        return False

    def _check_approach_abort(self, track: FlightTrack) -> AbortEvent | None:
        """
        THE KEY DETECTION: A flight on approach to DXB turns around.
        
        Pattern from yesterday's 9:00 attack:
          1. Flight is approaching DXB/AUH (distance decreasing, descending)
          2. Suddenly heading reverses — turns AWAY from the airport
          3. Distance to airport starts INCREASING
          4. Flight heads toward exiting UAE airspace
        
        This is the missile detection signal.
        """
        snaps = track.snapshots
        if len(snaps) < APPROACH_MIN_CLOSING_SNAPS + 2:
            return None
        
        fid = track.flight_id
        if fid in self._abort_alerted:
            return None
        
        last = snaps[-1]
        
        # Must be at flight speed
        if last.ground_speed < APPROACH_MIN_SPEED_KT:
            return None
        
        # Must have UAE destination
        dest = last.destination.upper().strip()
        is_uae_dest = dest in UAE_AIRPORTS_IATA or dest in UAE_AIRPORTS_ICAO
        if not is_uae_dest:
            return None
        
        # Calculate distances to nearest UAE airport over recent snapshots
        recent = snaps[-(APPROACH_MIN_CLOSING_SNAPS + 2):]
        dist_history: list[tuple[str, float]] = []
        for snap in recent:
            airport, d = self._nearest_uae_airport(snap.latitude, snap.longitude)
            dist_history.append((airport, d))
        
        # Phase 1: Was it on approach? (distance was decreasing)
        # Look at the first N snapshots — distance should decrease
        approach_phase = dist_history[:APPROACH_MIN_CLOSING_SNAPS]
        was_approaching = all(
            approach_phase[i][1] > approach_phase[i + 1][1] 
            for i in range(len(approach_phase) - 1)
        )
        if not was_approaching:
            return None
        
        # Phase 2: Did it abort? (distance is now increasing)
        min_dist_idx = min(range(len(dist_history)), key=lambda i: dist_history[i][1])
        min_dist_nm = dist_history[min_dist_idx][1]
        current_dist_nm = dist_history[-1][1]
        
        # Must have moved away by at least ABORT_DIST_INCREASE_NM
        if current_dist_nm - min_dist_nm < ABORT_DIST_INCREASE_NM:
            return None
        
        # Must be within reasonable approach distance at closest point
        if min_dist_nm > APPROACH_MAX_DIST_NM:
            return None
        
        # Check heading reversal
        snap_at_closest = recent[min_dist_idx]
        heading_at_closest = snap_at_closest.heading
        heading_now = last.heading
        heading_delta = abs(heading_now - heading_at_closest)
        if heading_delta > 180:
            heading_delta = 360 - heading_delta
        
        if heading_delta < ABORT_HEADING_REVERSAL_DEG:
            return None
        
        # ── ABORT CONFIRMED ─────────────────────────────────────────
        self._abort_alerted.add(fid)
        
        # Was it descending before abort?
        was_descending = 0.0
        if len(recent) >= 3:
            alt_before = recent[0].altitude
            alt_at_closest = snap_at_closest.altitude
            if alt_before > alt_at_closest + 500:  # Was descending by at least 500ft
                was_descending = 1.0
        
        closest_airport = dist_history[min_dist_idx][0]
        
        return AbortEvent(
            timestamp=time.time(),
            flight_id=fid,
            callsign=last.callsign or fid,
            airport=closest_airport,
            abort_distance_nm=min_dist_nm,
            heading_reversal_deg=heading_delta,
            altitude_at_abort_ft=snap_at_closest.altitude,
            was_descending=was_descending,
            speed_at_abort_kt=last.ground_speed,
            concurrent_aborts=0,  # Will be filled in by analyze()
            time_since_last_true=0.0,  # Will be filled in by analyze()
        )

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
        """Check for emergency squawk codes.
        
        7500 (hijack) and 7700 (emergency) = SIREN (genuinely critical).
        7600 (radio failure) = just log it (common, not an attack).
        """
        last = track.last
        if not last or not last.squawk:
            return

        if last.squawk == "7600":
            # Radio failure — common, not an emergency. Just log.
            logger.info(f"Squawk 7600 (RADIO FAILURE): {last.callsign} — not alerting")
            return

        if last.squawk in SQUAWK_EMERGENCY:
            labels = {
                "7500": "HIJACK",
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
                # Individual holding = silent log only. Mass holding handled in analyze().
                logger.info(
                    f"Holding pattern: {last.callsign} circling {direction} near {nearest_airport} "
                    f"({abs_cumulative:.0f}\u00b0 rotation). Alt: FL{last.altitude / 100:.0f}"
                )
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
        baseline_str = f"{self._baseline:.0f}" if self._baseline else "calc..."
        parts = [
            f"Active: {self.tracker.active_count}",
            f"Baseline: {baseline_str}",
        ]
        if self.approach_count > 0:
            parts.append(f"\033[96m✈→ Approach: {self.approach_count}\033[0m")
        if self.abort_count > 0:
            if self.abort_wave:
                parts.append(f"\033[91m\U0001f680 ABORT WAVE: {len(self._recent_aborts)}\033[0m")
            else:
                parts.append(f"\033[93m\u21a9 Abort: {self.abort_count}\033[0m")
        if self.holding_count > 0:
            parts.append(f"\033[93m\U0001f504 Hold: {self.holding_count}\033[0m")
        if self.spoof_count > 0:
            parts.append(f"\033[93m\U0001f4e1 Spoof: {self.spoof_count}\033[0m")
        return " | ".join(parts)

    # ── Housekeeping ─────────────────────────────────────────────────────────

    def _cleanup_detection_state(self):
        """Remove stale holding/spoof/abort alert IDs for flights no longer tracked."""
        active_ids = set(self.tracker.active_tracks.keys())
        self._holding_alerted = self._holding_alerted & active_ids
        self._spoof_alerted = self._spoof_alerted & active_ids
        # Keep abort_alerted a bit longer (don't re-alert same flight)
        # Only prune if flight is truly gone from all tracking
        all_ids = set(self.tracker._tracks.keys())
        self._abort_alerted = self._abort_alerted & all_ids
