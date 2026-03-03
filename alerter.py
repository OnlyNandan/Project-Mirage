"""
Project Mirage — Alert Dispatcher

Handles all alerting: macOS notifications + sound alerts (siren/ping).
Uses native osascript for notifications, afplay for sounds.
"""

import subprocess
import time
import logging
from dataclasses import dataclass, field
from enum import Enum

from config import ALERT_COOLDOWN_SEC, ALERT_SOUND
from sounds import ensure_sounds, play_siren, play_ping, stop_all

logger = logging.getLogger("mirage.alerter")


class Severity(Enum):
    INFO = "INFO"
    WARNING = "⚠️  WARNING"
    CRITICAL = "🚨 CRITICAL"


@dataclass
class Alert:
    severity: Severity
    title: str
    message: str
    flight_id: str | None = None
    source: str = "flight"          # "flight" or "osint"
    timestamp: float = field(default_factory=time.time)


class Alerter:
    """Handles alert dispatch with per-flight cooldowns and sound alerts."""

    def __init__(self):
        self._cooldowns: dict[str, float] = {}  # flight_id -> last_alert_time
        self._alert_history: list[Alert] = []
        # Generate sound files on init
        if ALERT_SOUND:
            ensure_sounds()

    def send(self, alert: Alert) -> bool:
        """
        Send an alert. Returns True if dispatched, False if suppressed by cooldown.
        """
        # Check cooldown for flight-specific alerts
        if alert.flight_id:
            last_time = self._cooldowns.get(alert.flight_id, 0)
            if time.time() - last_time < ALERT_COOLDOWN_SEC:
                logger.debug(f"Alert suppressed (cooldown): {alert.flight_id}")
                return False
            self._cooldowns[alert.flight_id] = time.time()

        self._alert_history.append(alert)

        # Log to console
        self._log_alert(alert)

        # Fire macOS notification
        self._notify_macos(alert)

        # Play sound
        if ALERT_SOUND:
            self._play_sound(alert)

        return True

    def shutdown(self):
        """Stop any playing sounds."""
        stop_all()

    def _log_alert(self, alert: Alert):
        """Print alert to terminal with color."""
        colors = {
            Severity.INFO: "\033[94m",       # Blue
            Severity.WARNING: "\033[93m",     # Yellow
            Severity.CRITICAL: "\033[91m",    # Red
        }
        reset = "\033[0m"
        color = colors.get(alert.severity, "")

        print(f"\n{color}{'━' * 60}")
        print(f"  {alert.severity.value}: {alert.title}")
        print(f"  {alert.message}")
        print(f"{'━' * 60}{reset}\n")

    def _play_sound(self, alert: Alert):
        """Play appropriate sound based on severity."""
        if alert.severity == Severity.CRITICAL:
            play_siren(repeat=3)
        else:
            play_ping()

    def _notify_macos(self, alert: Alert):
        """Send a native macOS notification via osascript."""
        # No built-in sound — we handle sounds ourselves via afplay
        script = (
            f'display notification "{self._escape(alert.message)}" '
            f'with title "Project Mirage" '
            f'subtitle "{self._escape(alert.severity.value + ": " + alert.title)}" '
        )

        try:
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5,
            )
            logger.debug("macOS notification sent.")
        except subprocess.TimeoutExpired:
            logger.warning("macOS notification timed out.")
        except Exception as e:
            logger.warning(f"Failed to send macOS notification: {e}")

    @staticmethod
    def _escape(text: str) -> str:
        """Escape special characters for AppleScript strings."""
        return text.replace("\\", "\\\\").replace('"', '\\"')

    def cleanup_cooldowns(self):
        """Remove expired cooldowns to prevent memory leak on long runs."""
        now = time.time()
        expired = [fid for fid, t in self._cooldowns.items()
                    if now - t > ALERT_COOLDOWN_SEC * 2]
        for fid in expired:
            del self._cooldowns[fid]

    @property
    def history(self) -> list[Alert]:
        return self._alert_history
