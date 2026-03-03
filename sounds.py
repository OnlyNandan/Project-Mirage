"""
Project Mirage — Sound Alert System

Generates and plays alert sounds:
  - CRITICAL: loud repeating siren (generated WAV)
  - WARNING/INFO: macOS system Ping sound

Uses only stdlib (wave, struct, math) + macOS afplay. Zero dependencies.
"""

import math
import os
import struct
import subprocess
import threading
import time
import wave
import logging

logger = logging.getLogger("mirage.sounds")

# Directory to store generated sound files
SOUNDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".sounds")
SIREN_PATH = os.path.join(SOUNDS_DIR, "siren.wav")
PING_PATH = "/System/Library/Sounds/Ping.aiff"
ALERT_PING_PATH = os.path.join(SOUNDS_DIR, "alert_ping.wav")

# Currently playing process (so we can kill it on shutdown)
_current_process: subprocess.Popen | None = None
_lock = threading.Lock()


def ensure_sounds():
    """Generate sound files if they don't exist."""
    os.makedirs(SOUNDS_DIR, exist_ok=True)
    if not os.path.exists(SIREN_PATH):
        _generate_siren(SIREN_PATH)
        logger.info("Generated siren sound.")
    if not os.path.exists(ALERT_PING_PATH):
        _generate_ping(ALERT_PING_PATH)
        logger.info("Generated alert ping sound.")


def play_siren(repeat: int = 3):
    """Play the siren sound (blocking, in a thread). Repeats N times."""
    def _play():
        for _ in range(repeat):
            _play_file(SIREN_PATH)
            time.sleep(0.1)
    t = threading.Thread(target=_play, daemon=True)
    t.start()


def play_ping():
    """Play a short ping/alert sound (non-blocking)."""
    def _play():
        if os.path.exists(ALERT_PING_PATH):
            _play_file(ALERT_PING_PATH)
        else:
            _play_file(PING_PATH)
    t = threading.Thread(target=_play, daemon=True)
    t.start()


def stop_all():
    """Kill any currently playing sound."""
    global _current_process
    with _lock:
        if _current_process and _current_process.poll() is None:
            _current_process.terminate()
            _current_process = None


def _play_file(path: str):
    """Play a sound file using macOS afplay."""
    global _current_process
    if not os.path.exists(path):
        logger.warning(f"Sound file not found: {path}")
        return
    try:
        with _lock:
            _current_process = subprocess.Popen(
                ["afplay", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        _current_process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        _current_process.terminate()
    except Exception as e:
        logger.warning(f"Failed to play sound: {e}")


# ─── Sound Generation ────────────────────────────────────────────────────────

def _generate_siren(path: str):
    """
    Generate a rising-falling siren WAV file.
    Two cycles of frequency sweep: 400Hz → 900Hz → 400Hz over ~2.5 seconds.
    """
    sample_rate = 44100
    duration = 2.5  # seconds
    num_samples = int(sample_rate * duration)
    amplitude = 28000

    samples = []
    for i in range(num_samples):
        t = i / sample_rate
        # Sweep frequency: sine wave modulation between 400-900 Hz
        # Two full sweep cycles over the duration
        sweep = math.sin(2 * math.pi * t * (2 / duration))  # 2 cycles
        freq = 650 + 250 * sweep  # 400–900 Hz range

        # Accumulate phase for smooth frequency changes
        phase = 0
        # For smooth phase, integrate frequency
        # Approximation: use instantaneous frequency
        phase = 2 * math.pi * (650 * t + 250 * (duration / (2 * math.pi * (2 / duration))) *
                                (-math.cos(2 * math.pi * t * (2 / duration)) + 1))

        sample = int(amplitude * math.sin(phase))
        samples.append(sample)

    _write_wav(path, samples, sample_rate)


def _generate_ping(path: str):
    """
    Generate a short attention-grabbing ping sound.
    A 880Hz tone with fast attack and decay, ~0.3 seconds.
    """
    sample_rate = 44100
    duration = 0.4
    num_samples = int(sample_rate * duration)
    amplitude = 22000
    freq = 880  # A5 note

    samples = []
    for i in range(num_samples):
        t = i / sample_rate
        # Exponential decay envelope
        envelope = math.exp(-t * 8)
        # Add a slight second harmonic for richness
        value = (math.sin(2 * math.pi * freq * t) * 0.8 +
                 math.sin(2 * math.pi * freq * 2 * t) * 0.2)
        sample = int(amplitude * envelope * value)
        samples.append(sample)

    _write_wav(path, samples, sample_rate)


def _write_wav(path: str, samples: list[int], sample_rate: int):
    """Write samples to a WAV file (mono, 16-bit)."""
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)  # 16-bit
        wf.setframerate(sample_rate)
        # Clamp samples to 16-bit range
        data = b"".join(
            struct.pack("<h", max(-32768, min(32767, s)))
            for s in samples
        )
        wf.writeframes(data)
