"""
passenger_wsgi.py — Namecheap cPanel / Phusion Passenger entry point

Passenger requires the WSGI callable to be named 'application'.
This file imports it from packetprobe_server and configures paths.
"""
import sys, os

# Add the app directory to Python path
INTERP = os.path.expanduser("~")
APP_DIR = os.path.dirname(os.path.abspath(__file__))

if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from packetprobe_server import application  # noqa: F401
