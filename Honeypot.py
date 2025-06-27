import socket
import logging
import threading
import subprocess
import smtplib
from email.mime.text import MIMEText
import geoip2  # For Geo-IP lookup
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime
import csv

# Ensure a folder exists for storing logs
log_folder = "Honeypot Logs"
os.makedirs(log_folder, exist_ok=True)

# Generate a new log file for each day
log_filename = os.path.join(log_folder, datetime.now().strftime("honeypot_%Y-%m-%d.log"))
logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to convert logs to CSV format
def log_to_csv(log_data):
    csv_filename = os.path.join(log_folder, datetime.now().strftime("honeypot_%Y-%m-%d.csv"))
    with open(csv_filename, "a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Timestamp", "Level", "Message"])
        for line in log_data.splitlines():
            parts = line.split(" - ", 2)  # Split log into timestamp, level, and message
            if len(parts) == 3:
                csv_writer.writerow(parts)

# Function to export logs to CSV
def export_logs_to_csv():
    try:
        with open(log_filename, "r") as log_file:
            log_data = log_file.read()
        log_to_csv(log_data)
        logging.info("Logs exported to CSV.")
    except Exception as e:
        logging.error(f"Failed to export logs to CSV: {str(e)}")

# Global variable to control honeypot state
running = False

# Function to start the honeypot server
def start_honeypot():
    global running
    running = True
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 2222))
    server_socket.listen(5)
    logging.info("Honeypot running on 0.0.0.0:2222...")

    while running:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client_socket, client_address), daemon=True).start()

# Function to stop the honeypot server
def stop_honeypot():
    global running
    running = False
    logging.info("Honeypot stopped.")
    messagebox.showinfo("Honeypot", "Honeypot has been stopped.")

# Function to handle incoming client connections
def handle_connection(client_socket, address):
    logging.info(f"Connection from {address[0]}:{address[1]} established.")
    geo_info = get_geo_ip_info(address[0])
    logging.info(f"Geo-IP Info: {geo_info}")

    try:
        while True:
            command = client_socket.recv(1024).decode("utf-8")
            if not command:
                break

            logging.info(f"Received command: {command} from {address[0]}:{address[1]}")

            if "sudo" in command or "su" in command:
                client_socket.send(b"Privilege escalation attempt detected.\n")
                logging.warning(f"Privilege escalation attempt from {address[0]}:{address[1]}")
            else:
                client_socket.send(b"Command received.\n")

    except Exception as e:
        logging.error(f"Error handling connection from {address[0]}:{address[1]}: {str(e)}")
    finally:
        client_socket.close()
        logging.info(f"Connection from {address[0]}:{address[1]} closed.")

# Function to get Geo-IP information, issues with licensing 
def get_geo_ip_info(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        return {
            "country": response.country.name or "Unknown",
            "city": response.city.name or "Unknown",
            "latitude": response.location.latitude or "Unknown",
            "longitude": response.location.longitude or "Unknown"
        }
    except Exception as e:
        logging.error(f"Geo-IP lookup failed for IP {ip} with error: {e}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": "Unknown",
            "longitude": "Unknown"
        }

# GUI Application
def main():
    def start_honeypot_thread():
        threading.Thread(target=start_honeypot, daemon=True).start()
        log_display.insert(tk.END, "Honeypot started...\n")

    def stop_honeypot_gui():
        stop_honeypot()
        log_display.insert(tk.END, "Honeypot stopped...\n")
        export_logs_to_csv()

    app = tk.Tk()
    app.title("Honeypot GUI")
    app.geometry("800x500")
    app.grid_rowconfigure(0, weight=1)
    app.grid_columnconfigure(0, weight=1)

    frame = tk.Frame(app)
    frame.grid(row=0, column=0, sticky="nsew")
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    log_display = scrolledtext.ScrolledText(frame, width=80, height=20, state='normal', wrap=tk.WORD)
    log_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    start_button = tk.Button(frame, text="Start Honeypot", command=start_honeypot_thread)
    start_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

    stop_button = tk.Button(frame, text="Stop Honeypot", command=stop_honeypot_gui)
    stop_button.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    def update_log_display():
        try:
            with open(log_filename, "r") as log_file:
                log_content = log_file.read()
                if log_display.get("1.0", tk.END).strip() != log_content.strip():
                    log_display.configure(state='normal')
                    log_display.delete(1.0, tk.END)
                    log_display.insert(tk.END, log_content)
                    log_display.configure(state='disabled')
        except FileNotFoundError:
            pass
        app.after(1000, update_log_display)

    update_log_display()
    app.mainloop()

if __name__ == "__main__":
    main()

