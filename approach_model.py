"""
Project Mirage — Approach-Abort ML Model

The core detection idea:
  A plane on approach to DXB (getting closer, descending) suddenly turns around
  and heads away → this is the pattern that happens during a missile/attack.

The model:
  - Scores each abort event with weighted features
  - Starts with sensible default weights (rule-based)
  - Learns from user feedback ("was there a boom?") after each siren
  - Stores labeled events in model_data.json
  - Adjusts weights so future scoring is better

Features extracted per abort:
  1. abort_distance_nm     — how close to airport at abort (closer = more suspicious)
  2. heading_reversal_deg  — how sharp the turn-away was
  3. altitude_at_abort_ft  — lower = more committed to landing before abort
  4. was_descending        — was it actually descending before abort? (1.0 / 0.0)
  5. speed_at_abort_kt     — approach speed
  6. concurrent_aborts     — other flights also aborting right now (most important!)
  7. time_since_last_true  — hours since last confirmed attack (recent = more likely)
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict

from config import MODEL_DATA_FILE, FEEDBACK_DELAY_SEC

logger = logging.getLogger("mirage.model")

# ─── Default weights (tuned by hand, adjusted by feedback) ───────────────────
DEFAULT_WEIGHTS = {
    "abort_distance_nm":     -1.5,   # Negative: closer = higher score
    "heading_reversal_deg":   0.8,   # Bigger turn = higher score
    "altitude_at_abort_ft":  -0.3,   # Lower altitude = higher score (was committed)
    "was_descending":         2.0,   # Was descending → strong signal
    "speed_at_abort_kt":      0.1,   # Higher speed = more real approach
    "concurrent_aborts":      5.0,   # Multiple planes aborting = strongest signal
    "time_since_last_true":  -0.5,   # Recent confirmed attacks → more likely
}

# Score threshold for triggering CRITICAL siren
DEFAULT_SIREN_THRESHOLD = 6.0


@dataclass
class AbortEvent:
    """A single approach-abort event with features for ML scoring."""
    timestamp: float
    flight_id: str
    callsign: str
    airport: str               # Which airport they were approaching
    
    # Features
    abort_distance_nm: float   # How close to airport when they turned
    heading_reversal_deg: float  # How sharp the turn-away was
    altitude_at_abort_ft: float  # Altitude at abort
    was_descending: float      # 1.0 if descending before abort, else 0.0
    speed_at_abort_kt: float   # Ground speed at abort
    concurrent_aborts: int     # Other flights also aborting right now
    time_since_last_true: float  # Hours since last confirmed attack
    
    # Computed
    score: float = 0.0         # ML score
    triggered_siren: bool = False
    
    # Feedback (filled in later by user)
    label: str | None = None   # "true" (real attack) or "false" (false positive)
    feedback_time: float | None = None


class ApproachAbortModel:
    """
    Learnable scoring model for approach-abort events.
    
    Starts with hand-tuned default weights.
    After each siren, asks the user for feedback.
    Uses feedback history to adjust weights with simple gradient updates.
    """

    def __init__(self, data_file: str = MODEL_DATA_FILE):
        self._data_file = data_file
        self._weights: dict[str, float] = dict(DEFAULT_WEIGHTS)
        self._siren_threshold: float = DEFAULT_SIREN_THRESHOLD
        self._events: list[dict] = []
        self._pending_feedback: list[AbortEvent] = []  # Events waiting for user feedback
        self._last_confirmed_attack: float = 0.0       # Epoch of last confirmed attack
        
        # Load saved model state
        self._load()

    # ── Scoring ──────────────────────────────────────────────────────────────

    def score(self, event: AbortEvent) -> float:
        """
        Score an abort event. Higher = more likely a real attack.
        
        Uses weighted sum of normalized features.
        """
        features = self._extract_features(event)
        total = 0.0
        for feat_name, feat_val in features.items():
            w = self._weights.get(feat_name, 0.0)
            total += w * feat_val
        
        event.score = total
        return total

    def should_siren(self, score: float) -> bool:
        """Should we trigger the siren for this score?"""
        return score >= self._siren_threshold

    def _extract_features(self, event: AbortEvent) -> dict[str, float]:
        """Normalize features for scoring."""
        return {
            "abort_distance_nm":     event.abort_distance_nm / 80.0,     # Normalize to ~0-1
            "heading_reversal_deg":  event.heading_reversal_deg / 180.0, # 0-1
            "altitude_at_abort_ft":  event.altitude_at_abort_ft / 20000.0,  # 0-1
            "was_descending":        event.was_descending,               # Already 0/1
            "speed_at_abort_kt":     min(event.speed_at_abort_kt / 400.0, 1.0),  # 0-1
            "concurrent_aborts":     min(event.concurrent_aborts / 3.0, 2.0),     # 0-2+
            "time_since_last_true":  min(event.time_since_last_true / 24.0, 1.0), # 0-1
        }

    # ── Event Recording ──────────────────────────────────────────────────────

    def record_event(self, event: AbortEvent):
        """Record an abort event. If it triggered siren, queue for feedback."""
        event_dict = {
            "timestamp": event.timestamp,
            "flight_id": event.flight_id,
            "callsign": event.callsign,
            "airport": event.airport,
            "abort_distance_nm": event.abort_distance_nm,
            "heading_reversal_deg": event.heading_reversal_deg,
            "altitude_at_abort_ft": event.altitude_at_abort_ft,
            "was_descending": event.was_descending,
            "speed_at_abort_kt": event.speed_at_abort_kt,
            "concurrent_aborts": event.concurrent_aborts,
            "time_since_last_true": event.time_since_last_true,
            "score": event.score,
            "triggered_siren": event.triggered_siren,
            "label": event.label,
            "feedback_time": event.feedback_time,
        }
        self._events.append(event_dict)
        
        if event.triggered_siren:
            self._pending_feedback.append(event)
        
        self._save()

    @property
    def time_since_last_confirmed(self) -> float:
        """Hours since last confirmed attack (for feature calculation)."""
        if self._last_confirmed_attack == 0:
            return 999.0  # Never seen an attack
        return (time.time() - self._last_confirmed_attack) / 3600.0

    # ── User Feedback ────────────────────────────────────────────────────────

    def get_pending_feedback(self) -> list[AbortEvent]:
        """Get events that are past the feedback delay and need user input."""
        now = time.time()
        ready = []
        for event in self._pending_feedback:
            if now - event.timestamp >= FEEDBACK_DELAY_SEC:
                ready.append(event)
        return ready

    def submit_feedback(self, event: AbortEvent, was_attack: bool):
        """User tells us if it was a real attack or false positive."""
        event.label = "true" if was_attack else "false"
        event.feedback_time = time.time()
        
        if was_attack:
            self._last_confirmed_attack = event.timestamp
        
        # Remove from pending
        self._pending_feedback = [e for e in self._pending_feedback 
                                   if e.timestamp != event.timestamp]
        
        # Update the stored event with feedback
        for stored in self._events:
            if abs(stored["timestamp"] - event.timestamp) < 1.0:
                stored["label"] = event.label
                stored["feedback_time"] = event.feedback_time
                break
        
        # Re-train weights with all labeled data
        self._update_weights()
        self._save()
        
        action = "CONFIRMED ATTACK" if was_attack else "false positive"
        logger.info(f"Feedback received: {event.callsign} → {action}")

    def dismiss_pending(self, event: AbortEvent):
        """Dismiss a feedback prompt without answering (treated as false)."""
        self.submit_feedback(event, was_attack=False)

    # ── Weight Learning ──────────────────────────────────────────────────────

    def _update_weights(self):
        """
        Simple online learning: adjust weights based on labeled data.
        
        For each labeled event:
          - If TRUE positive (real attack) and score was low → increase weights
            that contributed (push score up)
          - If FALSE positive (no attack) and score was high → decrease weights
            (push score down)
        
        Uses a simple perceptron-style update with learning rate.
        """
        labeled = [e for e in self._events if e.get("label") is not None]
        if not labeled:
            return
        
        lr = 0.1  # Learning rate
        
        for event_dict in labeled:
            label_val = 1.0 if event_dict["label"] == "true" else 0.0
            predicted = 1.0 if event_dict["score"] >= self._siren_threshold else 0.0
            error = label_val - predicted
            
            if abs(error) < 0.001:
                continue  # Already correct
            
            # Reconstruct normalized features
            features = {
                "abort_distance_nm":     event_dict["abort_distance_nm"] / 80.0,
                "heading_reversal_deg":  event_dict["heading_reversal_deg"] / 180.0,
                "altitude_at_abort_ft":  event_dict["altitude_at_abort_ft"] / 20000.0,
                "was_descending":        event_dict["was_descending"],
                "speed_at_abort_kt":     min(event_dict["speed_at_abort_kt"] / 400.0, 1.0),
                "concurrent_aborts":     min(event_dict["concurrent_aborts"] / 3.0, 2.0),
                "time_since_last_true":  min(event_dict["time_since_last_true"] / 24.0, 1.0),
            }
            
            # Perceptron update: w += lr * error * feature
            for feat_name, feat_val in features.items():
                self._weights[feat_name] += lr * error * feat_val
        
        # Also adjust threshold slightly
        true_scores = [e["score"] for e in labeled if e["label"] == "true"]
        false_scores = [e["score"] for e in labeled if e["label"] == "false"]
        
        if true_scores and false_scores:
            # Set threshold halfway between mean true and mean false
            mean_true = sum(true_scores) / len(true_scores)
            mean_false = sum(false_scores) / len(false_scores)
            if mean_true > mean_false:
                self._siren_threshold = (mean_true + mean_false) / 2.0
                logger.info(f"Model threshold adjusted to {self._siren_threshold:.2f}")
        
        logger.info(f"Model weights updated with {len(labeled)} labeled events")
        logger.debug(f"Weights: {self._weights}")

    # ── Persistence ──────────────────────────────────────────────────────────

    def _save(self):
        """Save model state to JSON file."""
        data = {
            "weights": self._weights,
            "siren_threshold": self._siren_threshold,
            "last_confirmed_attack": self._last_confirmed_attack,
            "events": self._events[-500:],  # Keep last 500 events
        }
        try:
            with open(self._data_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save model data: {e}")

    def _load(self):
        """Load model state from JSON file if it exists."""
        if not os.path.exists(self._data_file):
            logger.info("No model data found — starting with defaults")
            return
        
        try:
            with open(self._data_file) as f:
                data = json.load(f)
            
            if "weights" in data:
                # Merge with defaults (in case new features were added)
                for key, val in data["weights"].items():
                    if key in self._weights:
                        self._weights[key] = val
            
            self._siren_threshold = data.get("siren_threshold", DEFAULT_SIREN_THRESHOLD)
            self._last_confirmed_attack = data.get("last_confirmed_attack", 0.0)
            self._events = data.get("events", [])
            
            labeled = len([e for e in self._events if e.get("label")])
            logger.info(
                f"Model loaded: {len(self._events)} events ({labeled} labeled), "
                f"threshold={self._siren_threshold:.2f}"
            )
        except Exception as e:
            logger.warning(f"Failed to load model data: {e}")

    # ── Status ───────────────────────────────────────────────────────────────

    @property
    def stats(self) -> str:
        """Human-readable model stats."""
        total = len(self._events)
        labeled = len([e for e in self._events if e.get("label")])
        true_pos = len([e for e in self._events if e.get("label") == "true"])
        false_pos = len([e for e in self._events if e.get("label") == "false"])
        pending = len(self._pending_feedback)
        return (
            f"Events: {total} | Labeled: {labeled} "
            f"(TP: {true_pos}, FP: {false_pos}) | "
            f"Pending: {pending} | Threshold: {self._siren_threshold:.1f}"
        )
