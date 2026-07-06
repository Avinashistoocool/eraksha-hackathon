# live_nmap_flow_generator.py - REAL DEVICE SCANNER
# Scans your actual network for phones, laptops, etc.
# No decoy devices - discovers and monitors real devices only

import sqlite3
import time
import random
import subprocess
import sys
from datetime import datetime

DB_PATH = 'dataflows.db'
NETWORK = '10.194.0.0/16'  # Your lab network - adjust subnet if needed


def create_tables():
    """Create fresh database tables"""
    print("Setting up database...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # DROP old tables to remove decoy data
    cursor.execute('DROP TABLE IF EXISTS flows')
    cursor.execute('DROP TABLE IF EXISTS devices')

    cursor.execute('''
        CREATE TABLE devices (
            id TEXT PRIMARY KEY,
            name TEXT,
            devicetype TEXT,
            ip TEXT UNIQUE,
            port INTEGER,
            mac TEXT,
            vendor TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_id TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            anomaly_score REAL DEFAULT 0.0,
            anomaly INTEGER DEFAULT 0,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Fresh database ready (old decoys removed)")


def discover_real_devices():
    """Scan network for real devices (phones, laptops, etc.)"""
    print(f"\n🔍 Scanning {NETWORK} for real devices...")
    print("   (This may take 30-60 seconds)\n")

    devices = []
    try:
        # -sn: ping scan, -O: OS detection (needs root/admin)
        # Using just -sn for speed; add -O if running as admin
        result = subprocess.run(
            ['nmap', '-sn', NETWORK, '-T4', '--open'],
            capture_output=True, text=True, timeout=120
        )

        current_ip = None
        current_mac = None
        current_vendor = None

        for line in result.stdout.split('\n'):
            if 'Nmap scan report for' in line:
                # Save previous device
                if current_ip:
                    devices.append({
                        'ip': current_ip,
                        'mac': current_mac,
                        'vendor': current_vendor
                    })
                # Parse new IP
                parts = line.split()
                current_ip = parts[-1].strip('()')
                current_mac = None
                current_vendor = None

            elif 'MAC Address:' in line:
                # Parse MAC and vendor
                parts = line.split('MAC Address: ')[1]
                mac_parts = parts.split(' ', 1)
                current_mac = mac_parts[0]
                if len(mac_parts) > 1:
                    current_vendor = mac_parts[1].strip('()')

        # Don't forget last device
        if current_ip:
            devices.append({
                'ip': current_ip,
                'mac': current_mac,
                'vendor': current_vendor
            })

        # Filter to only 10.194.x.x
        devices = [d for d in devices if d['ip'].startswith('10.194.')]

        print(f"📱 Found {len(devices)} real devices:\n")
        print(f"{'IP':<18} {'MAC':<20} {'Vendor'}")
        print("-" * 70)
        for d in devices:
            print(f"{d['ip']:<18} {(d['mac'] or 'N/A'):<20} {d['vendor'] or 'Unknown'}")
        print()

        return devices

    except FileNotFoundError:
        print("❌ nmap not found! Install from https://nmap.org/download.html")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("⏱️ Scan timeout - using partial results")
        return devices
    except Exception as e:
        print(f"❌ Discovery error: {e}")
        return []


def guess_device_type(vendor, ip):
    """Guess device type from vendor string"""
    if not vendor:
        return 'unknown'
    vendor_lower = vendor.lower()

    if any(x in vendor_lower for x in ['apple', 'iphone', 'ipad']):
        return 'phone/tablet'
    elif any(x in vendor_lower for x in ['samsung', 'xiaomi', 'oneplus', 'oppo', 'vivo', 'realme']):
        return 'phone'
    elif any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'intel']):
        return 'laptop/pc'
    elif any(x in vendor_lower for x in ['tp-link', 'netgear', 'cisco', 'd-link', 'router']):
        return 'router/network'
    elif any(x in vendor_lower for x in ['amazon', 'google', 'sonos']):
        return 'smart-device'
    elif any(x in vendor_lower for x in ['raspberry', 'espressif', 'arduino']):
        return 'iot-board'
    else:
        return 'unknown'


def scan_ports(ip):
    """Quick port scan on device"""
    common_ports = [22, 23, 53, 80, 443, 445, 3389, 5353, 8080, 8443, 62078]  # 62078 = iPhone
    try:
        cmd = ['nmap', ip, '-p', ','.join(map(str, common_ports)), '--open', '-T4']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        open_ports = []
        for line in result.stdout.split('\n'):
            if '/open/' in line or '/tcp' in line and 'open' in line:
                try:
                    port = int(line.split('/')[0].strip())
                    open_ports.append(port)
                except:
                    pass
        return open_ports
    except:
        return []


def generate_flow(device, open_ports):
    """Generate a flow record from scan results"""
    bytes_sent = random.randint(300, 3000)
    bytes_received = random.randint(100, 1500)
    protocol = random.choice(['TCP', 'UDP'])
    dst_port = random.choice(open_ports) if open_ports else random.choice
