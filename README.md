Features
-Listens for incoming connections on port 2222
-Logs IP, commands, and connection data with timestamps
-Detects sudo/su privilege escalation attempts
-Performs Geo-IP lookups using MaxMind GeoLite2 database
-Real-time log viewer in the GUI
-Daily log rotation and CSV export support

How It Works
-The honeypot starts a TCP listener and waits for client connections
-Each connection is logged and processed in a separate thread
-Commands are logged, and suspicious actions are flagged
-Geo-IP data is collected from the attacker's IP address
-Logs are saved in a daily file and can be exported to CSV

Requirements
Python 3.x

tkinter (standard in most Python distributions)

geoip2
To install dependencies, run:
pip install geoip2

You will also need the GeoLite2-City.mmdb database file from MaxMind placed in the same directory.

Usage
Run the script:
python Honeypot.py

Use the GUI to:

Start the honeypot listener

View real-time logs

Stop the honeypot and export logs to CSV

Notes
Run with administrative privileges to ensure binding to ports and logging

Use only on isolated or authorized testing networks

Not a full SSH implementation — intended for basic deception and data gathering

License
This project is open-source and available under the MIT License.
