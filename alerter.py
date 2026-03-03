"""
Project Mirage — macOS Desktop Notification Alerter

Uses native osascript (AppleScript) for zero-dependency macOS notifications.
"""

import subprocess
import time
import logging
from dataclasses import dataclass, field
from enum import Enum

from config import ALERT_COOLDOWN_SEC, ALERT_SOUND

logger = logging.getLogger("mirage.alerter")


class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    severity: Severity
    title: str
    message: str
    flight_id: str | None = None
    timestamp: float = field(default_factory=time.time)


class Alerter:
    """Handles alert dispatch with per-flight cooldowns."""

    def __init__(self):
        self._cooldowns: dict[str, float] = {}  # flight_id -> last_alert_time
        self._alert_history: list[Alert] = []

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

        return True

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

    def _notify_macos(self, alert: Alert):
        """Send a native macOS notification via osascript."""
        sound_clause = 'sound name "Funk"' if ALERT_SOUND else ""
        if alert.severity == Severity.CRITICAL:
            sound_clause = 'sound name "Sosumi"'

        script = (
            f'display notification "{self._escape(alert.message)}" '
            f'with title "Project Mirage" '
            f'subtitle "{self._escape(alert.severity.value + ": " + alert.title)}" '
            f'{sound_clause}'
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
