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

# ─── OSINT — Social / News Monitoring ────────────────────────────────────────
# Sources (all free, no API keys)
OSINT_GOOGLE_NEWS_ENABLED = True
OSINT_REDDIT_ENABLED = True
OSINT_REDDIT_SUBREDDITS = ["worldnews", "dubai", "CombatFootage", "geopolitics"]

# Polling (OSINT runs on same cycle as FR24)
OSINT_DEDUP_WINDOW_SEC = 3600       # Don't re-alert same news item for 1 hour

# Critical keywords — trigger CRITICAL (siren) alert
OSINT_CRITICAL_KEYWORDS = [
    "missile launch",
    "missile strike",
    "ballistic missile",
    "cruise missile",
    "air strike",
    "airstrike",
    "airspace closed",
    "airport closed",
    "airport attack",
    "drone attack",
    "drone strike",
    "NOTAM closed",
    "war declared",
    "military strike",
    "bombing",
    "explosion",
    "evacuate",
    "civil defense",
    "air defense",
    "iron dome",
    "intercepted missile",
    "DXB closed",
    "AUH closed",
]

# General keywords — trigger WARNING (ping) alert
OSINT_KEYWORDS = [
    "UAE threat",
    "Dubai threat",
    "Abu Dhabi threat",
    "DXB divert",
    "DXB emergency",
    "NOTAM",
    "airspace restriction",
    "flight diversion",
    "military activity",
    "Houthi",
    "escalation",
    "conflict",
    "tensions",
    "sanctions",
    "retaliation",
    "ceasefire broken",
    "no-fly zone",
]

# ─── Display ─────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║             PROJECT MIRAGE — Threat Monitor              ║
║      FlightRadar24 + OSINT Intelligence Platform         ║
╚══════════════════════════════════════════════════════════╝
"""
