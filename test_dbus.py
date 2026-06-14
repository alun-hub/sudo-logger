import os
import dbus
try:
    bus = dbus.SessionBus()
    print("Successfully connected to session bus")
except Exception as e:
    print(f"Failed to connect to session bus: {e}")
