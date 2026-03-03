"""
Project Mirage — UAE Airspace Monitor Configuration
"""

# ─── UAE Airspace Bounding Box ───────────────────────────────────────────────
# Format expected by FlightRadarAPI: "north_lat,south_lat,west_lon,east_lon"
UAE_BOUNDS = {
    "north": 26.5,   # Top latitude
    "south": 22.5,   # Bottom latitude
    "west": 51.0,    # Left longitude
    "east": 56.5,    # Right longitude
}
UAE_BOUNDS_STR = f"{UAE_BOUNDS['north']},{UAE_BOUNDS['south']},{UAE_BOUNDS['west']},{UAE_BOUNDS['east']}"

# ─── UAE Airports (IATA codes) ───────────────────────────────────────────────
# Used to determine if a flight leaving the box was expected (destination outside UAE)
# or unexpected (diversion — destination was a UAE airport but it left)
UAE_AIRPORTS_IATA = {"DXB", "AUH", "SHJ", "DWC", "RKT", "AAN", "FJR"}
UAE_AIRPORTS_ICAO = {"OMDB", "OMAA", "OMSJ", "OMDW", "OMRK", "OMAL", "OMFJ"}

# ─── Polling ─────────────────────────────────────────────────────────────────
POLL_INTERVAL_SEC = 15          # Seconds between FR24 API calls
STARTUP_GRACE_POLLS = 3         # Number of initial polls before detection activates
                                # (lets us build a baseline first)

# ─── Diversion Detection — Individual Flights ────────────────────────────────
HEADING_CHANGE_THRESHOLD_DEG = 60   # Flag if heading changes > this in one poll cycle
MIN_TRACK_TIME_SEC = 60             # Ignore flights seen for less than this
MAX_HISTORY_SNAPSHOTS = 40          # Keep last N snapshots per flight (~10 min at 15s)
ALTITUDE_FLOOR_FT = 5000           # Ignore ground-level traffic (taxiing, etc.)

# ─── Diversion Detection — Airspace Emptying ─────────────────────────────────
BASELINE_WINDOW = 10                # Rolling average over last N polls
FLIGHT_COUNT_DROP_PERCENT = 30      # Alert if count drops > this % below baseline
CRITICAL_MIN_FLIGHTS = 2           # If total flights drop below this, always alert

# Time-of-day thresholds (UAE time, 24h)
# Late night has fewer flights — relax thresholds to avoid false positives
QUIET_HOURS = (0, 6)                # 12am–6am UAE time
QUIET_HOUR_DROP_PERCENT = 50        # More lenient during quiet hours

# ─── Alerting ────────────────────────────────────────────────────────────────
ALERT_COOLDOWN_SEC = 300            # Don't re-alert same flight within 5 minutes
ALERT_SOUND = True                  # Play macOS alert sound with notification

# ─── Display ─────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║           PROJECT MIRAGE — UAE Airspace Monitor          ║
║         FlightRadar24 Diversion Detection System         ║
╚══════════════════════════════════════════════════════════╝
"""
