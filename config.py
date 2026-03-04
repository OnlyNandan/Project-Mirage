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

# ─── Holding Pattern Detection ───────────────────────────────────────────────
# Detect flights circling (cumulative heading change > 360° over recent history)
# This is what happens when flights can't land (airspace threat, attack, etc.)
HOLDING_CUMULATIVE_DEG = 360        # Total heading rotation to flag as holding
HOLDING_MIN_SNAPSHOTS = 8           # Min snapshots to check (avoids noise)
HOLDING_MAX_ALTITUDE_FT = 20000     # Holding usually below FL200
HOLDING_MAX_DISTANCE_NM = 60        # Must be within 60nm of a UAE airport

# ─── GPS Spoofing Detection ──────────────────────────────────────────────────
# GPS spoofing is active in the Middle East — detect anomalies
SPOOF_MAX_SPEED_KT = 700            # Faster than this between polls = teleport (spoofing)
SPOOF_HEADING_MISMATCH_DEG = 90     # Heading vs actual movement vector differ > this
SPOOF_CLUSTER_RADIUS_DEG = 0.01     # ~1km — multiple flights at same fake position
SPOOF_CLUSTER_MIN_FLIGHTS = 3       # Min flights in cluster to flag

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

# ─── Approach Abort Detection (the core ML model) ────────────────────────────
# The pattern: plane is on approach to DXB → suddenly turns around → exits UAE
# That means a missile/attack. This is the primary siren trigger.
APPROACH_MAX_DIST_NM = 80           # Consider "on approach" if within 80nm of airport
APPROACH_MIN_CLOSING_SNAPS = 3      # Must be closing in for at least 3 snapshots
APPROACH_MIN_SPEED_KT = 150         # Must be at flight speed (not parked/taxiing)
ABORT_HEADING_REVERSAL_DEG = 90     # Turn-away threshold (heading change toward exit)
ABORT_DIST_INCREASE_NM = 2.0        # Must be moving away from airport by at least this
ABORT_CONCURRENT_THRESHOLD = 2      # 2+ aborts at same time = almost certainly attack

# ML model feedback
MODEL_DATA_FILE = "model_data.json"  # Stores labeled events for learning
FEEDBACK_DELAY_SEC = 300             # Ask user 5 min after siren: "was there a boom?"

# ─── Display ─────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║             PROJECT MIRAGE — Threat Monitor              ║
║       FlightRadar24 Approach-Abort ML Detection          ║
╚══════════════════════════════════════════════════════════╝
"""
