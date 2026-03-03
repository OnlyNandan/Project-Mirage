"""
Project Mirage — Flight State Tracker

Maintains a rolling history of every flight observed in the UAE bounding box.
Identifies flights that have entered, exited, or changed behavior.
"""

import time
import logging
from dataclasses import dataclass, field

from config import MAX_HISTORY_SNAPSHOTS, MIN_TRACK_TIME_SEC, ALTITUDE_FLOOR_FT

logger = logging.getLogger("mirage.tracker")


@dataclass
class FlightSnapshot:
    """A single point-in-time observation of a flight."""
    flight_id: str
    callsign: str
    latitude: float
    longitude: float
    heading: float
    altitude: float          # feet
    ground_speed: float      # knots
    origin: str              # IATA airport code
    destination: str         # IATA airport code
    aircraft_code: str
    airline_icao: str
    registration: str
    squawk: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class FlightTrack:
    """Full tracking history for one flight."""
    flight_id: str
    first_seen: float
    snapshots: list[FlightSnapshot] = field(default_factory=list)

    @property
    def last(self) -> FlightSnapshot | None:
        return self.snapshots[-1] if self.snapshots else None

    @property
    def prev(self) -> FlightSnapshot | None:
        return self.snapshots[-2] if len(self.snapshots) >= 2 else None

    @property
    def duration_sec(self) -> float:
        if not self.snapshots:
            return 0
        return self.snapshots[-1].timestamp - self.first_seen

    @property
    def is_mature(self) -> bool:
        """Has the flight been tracked long enough to be meaningful?"""
        return self.duration_sec >= MIN_TRACK_TIME_SEC

    def add_snapshot(self, snap: FlightSnapshot):
        self.snapshots.append(snap)
        # Trim old snapshots to cap memory
        if len(self.snapshots) > MAX_HISTORY_SNAPSHOTS:
            self.snapshots = self.snapshots[-MAX_HISTORY_SNAPSHOTS:]


class Tracker:
    """
    Central flight tracking engine.

    On each poll cycle, call update() with the list of raw flight objects
    from FlightRadar24. The tracker returns:
        - new_flights:  flights seen for the first time
        - exited_flights: flights that were tracked but are no longer in the box
        - active_flights: currently tracked flights
    """

    def __init__(self):
        self._tracks: dict[str, FlightTrack] = {}      # flight_id -> track
        self._current_ids: set[str] = set()             # IDs from latest poll
        self._previous_ids: set[str] = set()            # IDs from previous poll
        self._poll_count: int = 0

    def update(self, raw_flights: list) -> tuple[list[FlightTrack], list[FlightTrack]]:
        """
        Process a new batch of flights from FR24.

        Args:
            raw_flights: list of Flight objects from FlightRadarAPI

        Returns:
            (new_tracks, exited_tracks)
        """
        now = time.time()
        self._poll_count += 1
        self._previous_ids = self._current_ids.copy()
        self._current_ids = set()

        new_tracks: list[FlightTrack] = []
        exited_tracks: list[FlightTrack] = []

        # Process current flights
        for flight in raw_flights:
            fid = str(flight.id)
            snap = self._make_snapshot(flight, now)

            if not snap:
                continue

            # Filter out low-altitude traffic
            if snap.altitude < ALTITUDE_FLOOR_FT:
                continue

            self._current_ids.add(fid)

            if fid not in self._tracks:
                # New flight entering the box
                track = FlightTrack(flight_id=fid, first_seen=now)
                track.add_snapshot(snap)
                self._tracks[fid] = track
                new_tracks.append(track)
                logger.debug(f"New flight: {snap.callsign} ({snap.aircraft_code}) → {snap.destination}")
            else:
                # Known flight — update
                self._tracks[fid].add_snapshot(snap)

        # Detect flights that left the bounding box
        departed_ids = self._previous_ids - self._current_ids
        for fid in departed_ids:
            track = self._tracks.get(fid)
            if track and track.is_mature:
                exited_tracks.append(track)
                logger.debug(
                    f"Flight exited: {track.last.callsign if track.last else fid}"
                )

        # Prune stale tracks (gone for > 5 minutes)
        self._prune_stale(now)

        return new_tracks, exited_tracks

    def get_track(self, flight_id: str) -> FlightTrack | None:
        return self._tracks.get(flight_id)

    @property
    def active_tracks(self) -> dict[str, FlightTrack]:
        """All currently active (seen in last poll) tracks."""
        return {fid: self._tracks[fid] for fid in self._current_ids if fid in self._tracks}

    @property
    def active_count(self) -> int:
        return len(self._current_ids)

    @property
    def total_tracked(self) -> int:
        return len(self._tracks)

    @property
    def poll_count(self) -> int:
        return self._poll_count

    def _make_snapshot(self, flight, now: float) -> FlightSnapshot | None:
        """Convert a FlightRadarAPI Flight object to our FlightSnapshot."""
        try:
            return FlightSnapshot(
                flight_id=str(flight.id),
                callsign=getattr(flight, "callsign", "") or "",
                latitude=float(flight.latitude),
                longitude=float(flight.longitude),
                heading=float(flight.heading),
                altitude=float(flight.altitude),
                ground_speed=float(flight.ground_speed),
                origin=getattr(flight, "origin_airport_iata", "") or "",
                destination=getattr(flight, "destination_airport_iata", "") or "",
                aircraft_code=getattr(flight, "aircraft_code", "") or "",
                airline_icao=getattr(flight, "airline_icao", "") or "",
                registration=getattr(flight, "registration", "") or "",
                squawk=str(getattr(flight, "squawk", "") or ""),
                timestamp=now,
            )
        except (ValueError, AttributeError, TypeError) as e:
            logger.warning(f"Skipping malformed flight data: {e}")
            return None

    def _prune_stale(self, now: float):
        """Remove tracks that haven't been seen for a long time."""
        stale_ids = []
        for fid, track in self._tracks.items():
            if fid not in self._current_ids:
                if track.last and (now - track.last.timestamp) > 600:  # 10 min
                    stale_ids.append(fid)
        for fid in stale_ids:
            del self._tracks[fid]
            logger.debug(f"Pruned stale track: {fid}")
