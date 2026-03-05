# Project Mirage — UAE Threat Monitor

A real-time airspace monitoring system that uses FlightRadar24 API to track aircraft approaching Dubai International Airport (DXB) and detects unexpected approach-abort patterns indicative of potential threats.

## Overview

Project Mirage continuously monitors UAE airspace for aircraft that:
- Enter designated approach paths to DXB
- Abort landing or unexpectedly divert from their intended destination
- Exhibit anomalous heading changes or altitude deviations

When a potential threat is detected, the system triggers audio/visual alerts and collects user feedback to continuously improve its machine learning detection model.

## Features

- **Real-time Flight Tracking**: Monitors live aircraft positions via FlightRadar24 API
- **Approach Detection**: Identifies planes entering controlled approach paths
- **Abort Detection**: Flags unexpected approach cancellations and diversions
- **Machine Learning Feedback**: Learns from user feedback to reduce false positives
- **Audio Alerts**: Siren notifications with customizable sound options
- **Configurable Sensitivity**: Adjustable parameters for approach detection thresholds

## Installation

### Requirements

- Python 3.7+
- macOS (with audio support for alerts)

### Setup

1. Clone the repository and navigate to the project:
   ```bash
   cd Project-Mirage
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Operation

Start the monitor with default settings:
```bash
python main.py
```

### Command-Line Options

- `--verbose` – Enable debug logging for troubleshooting
- `--interval SECONDS` – Set custom poll interval (default: 15s)
- `--test-alert` – Send a test notification and exit
- `--no-sound` – Disable audio alerts

### Examples

Monitor with 30-second polling interval and debug output:
```bash
python main.py --interval 30 --verbose
```

Test alert system:
```bash
python main.py --test-alert
```

Run without sound alerts:
```bash
python main.py --no-sound
```

## Project Structure

- **main.py** – Core application loop and command-line interface
- **tracker.py** – Flight tracking and historical state management
- **detector.py** – Detects approach-abort patterns and anomalies
- **approach_model.py** – Machine learning model for approach behavior
- **alerter.py** – Alert generation and notification system
- **sounds.py** – Audio alert playback management
- **osint.py** – Open-source intelligence utilities
- **config.py** – Centralized configuration and constants

## Configuration

Edit `config.py` to customize:

- **UAE_BOUNDS** – Monitored airspace coordinates
- **POLL_INTERVAL_SEC** – Frequency of FlightRadar24 API queries
- **HEADING_CHANGE_THRESHOLD_DEG** – Sensitivity for abort detection
- **ALTITUDE_FLOOR_FT** – Minimum altitude for tracking
- **FEEDBACK_DELAY_SEC** – Time before requesting feedback (default: 5 min)

## How It Works

1. **Data Collection** – Polls FlightRadar24 API every 15 seconds for aircraft in UAE airspace
2. **Tracking** – Maintains historical snapshots of each flight's position, altitude, and heading
3. **Pattern Detection** – Analyzes heading changes, altitude drops, and diversion attempts
4. **Alert Generation** – Triggers sirens and notifications on suspicious patterns
5. **Feedback Learning** – Prompts user after 5 minutes with "was there a boom?" to improve model accuracy

## Alert Severity Levels

- **CRITICAL** – Immediate threat response (siren activation)
- **HIGH** – Elevated threat (alarm sound)
- **MEDIUM** – Suspicious pattern (tone alert)
- **INFO** – Status updates (logging only)

## Dependencies

- **FlightRadarAPI** – Flight tracking and real-time data
- **beautifulsoup4** – Web scraping and data parsing

## Performance Considerations

- Keeps last 40 flight snapshots per aircraft (~10 minutes at 15s intervals)
- Filters ground-level traffic below 5,000 ft (taxiing)
- Startup grace period of ~45 seconds before detection activates (baseline establishment)

## Notes

- Requires internet connection for FlightRadar24 API access
- Audio alerts require macOS with audio output capabilities
- System operates 24/7 for continuous airspace monitoring
- Machine learning model improves with user feedback over time

## License

Proprietary – Project Mirage

## Author

Nandan R
