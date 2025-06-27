# Python SSH Honeypot

A lightweight Python honeypot that listens for incoming connections on port 2222, logs connection data and commands with timestamps, detects privilege escalation attempts, and performs Geo-IP lookups. Includes a real-time GUI log viewer and supports daily log rotation with CSV export.

## Features
- Listens on TCP port 2222 for incoming connections
- Logs IP addresses, commands, and connection details with timestamps
- Detects sudo and su privilege escalation attempts
- Performs Geo-IP lookups using MaxMind GeoLite2 database
- Real-time log viewer GUI with start/stop controls
- Daily log rotation and CSV export support

## How It Works
- Starts a TCP listener to accept client connections
- Logs each connection and processes it in a separate thread
- Flags suspicious commands and privilege escalations
- Retrieves Geo-IP data for connecting IP addresses
- Saves logs daily with option to export to CSV

## Requirements
- Python 3.x
- tkinter (usually included with Python)
- geoip2 library (`pip install geoip2`)
- MaxMind GeoLite2-City.mmdb database file placed in the script directory

## Usage
Run the script:

Use the GUI to:
- Start the honeypot listener
- View real-time logs
- Stop the honeypot and export logs to CSV

## Notes
- Requires administrative privileges to bind ports and log properly
- Intended for use on isolated or authorized test networks only
- Not a full SSH server implementation; designed for deception and data collection

## License
MIT License
