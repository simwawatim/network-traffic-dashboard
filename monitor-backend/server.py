import requests
import threading
from datetime import datetime
from fastapi import Depends, FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Local imports
from authentication.connection.database import get_db, engine, Base
from authentication.urls import user_router
from devices import NetworkDeviceMonitor
from traffic import NetworkMonitor

# Initialize FastAPI app
app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Start device monitor thread
device_monitor = NetworkDeviceMonitor()
threading.Thread(target=device_monitor.start, daemon=True).start()

# Start traffic monitor
traffic_monitor = NetworkMonitor(interface="wlp3s0")
traffic_monitor.start()

# Include user routes (where /register is defined)
app.include_router(user_router.router)

# Devices endpoint
@app.get("/devices")
def get_devices():
    return [
        {
            "mac": mac,
            "ip": info["ip"],
            "name": info["name"],
            "last_seen": info["last_seen"].strftime('%Y-%m-%d %H:%M:%S'),
            "status": info["status"],
            "activity": device_monitor.arp_table.get(mac, 0),
        }
        for mac, info in device_monitor.devices.items()
    ]

# Traffic statistics endpoint
@app.get("/traffic")
def get_traffic_stats():
    return traffic_monitor.get_stats()

# IP geolocation using ipapi
@app.get("/ip-location")
def get_ip_location(ip: str):
    access_key = "1f4521d9dad629fc017125a079c50709"
    url = f"https://api.ipapi.com/{ip}?access_key={access_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if 'error' in data:
            return {"error": data['error']}
        return data
    except Exception as e:
        return {"error": str(e)}
