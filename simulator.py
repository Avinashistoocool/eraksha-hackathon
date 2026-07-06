import sqlite3
import json
import random
import time
from datetime import datetime, timedelta
import os

# Create data folder if not exists
os.makedirs('data', exist_ok=True)

DB_PATH = 'data/flows.db'


def init_db():
    """Create database and tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            duration REAL,
            device_id TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT,
            device_type TEXT,
            ip TEXT,
            port INTEGER,
            expected_bandwidth_kb INTEGER
        )
    ''')

    conn.commit()
    conn.close()


def load_devices():
    """Load devices from JSON"""
    with open('devices.json', 'r') as f:
        data = json.load(f)
    return data['devices']


def insert_devices(devices):
    """Insert devices into database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for device in devices:
        cursor.execute('''
            INSERT OR REPLACE INTO devices 
            (id, name, device_type, ip, port, expected_bandwidth_kb)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device['id'],
            device['name'],
            device['type'],
            device['ip'],
            device['port'],
            device['expected_bandwidth_kb']
        ))

    conn.commit()
    conn.close()


def generate_flow(device):
    """Generate a simulated network flow"""
    # Normal traffic patterns
    if device['type'] == 'camera':
        bytes_sent = random.randint(80000, 120000)  # 80-120 KB
        bytes_received = random.randint(1000, 5000)
    elif device['type'] == 'speaker':
        bytes_sent = random.randint(1000, 5000)
        bytes_received = random.randint(40000, 60000)  # 40-60 KB
    else:  # thermostat
        bytes_sent = random.randint(400, 600)
        bytes_received = random.randint(400, 600)

    # 10% chance of anomaly (unusual pattern)
    if random.random() < 0.1:
        anomaly_type = random.choice([1, 2, 3])
        if anomaly_type == 1:  # Unusually large transfer
            bytes_sent *= random.randint(5, 10)
        elif anomaly_type == 2:  # Different destination
            pass  # Handled below
        else:  # High frequency
            pass  # Handled below

    # Random destination
    dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

    # Random port
    dst_port = random.choice([80, 443, 8080, 53, 5353, 8888, 22, 21])

    flow = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': device['ip'],
        'dst_ip': dst_ip,
        'src_port': device['port'],
        'dst_port': dst_port,
        'protocol': random.choice(['TCP', 'UDP']),
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_received,
        'duration': random.uniform(0.5, 10.0),
        'device_id': device['id']
    }

    return flow


def insert_flow(flow):
    """Insert flow into database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO flows 
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
         bytes_sent, bytes_received, duration, device_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        flow['timestamp'],
        flow['src_ip'],
        flow['dst_ip'],
        flow['src_port'],
        flow['dst_port'],
        flow['protocol'],
        flow['bytes_sent'],
        flow['bytes_received'],
        flow['duration'],
        flow['device_id']
    ))

    conn.commit()
    conn.close()


def main():
    """Main simulator loop"""
    print("[*] Initializing database...")
    init_db()

    print("[*] Loading devices from devices.json...")
    devices = load_devices()
    insert_devices(devices)

    print(f"[✓] Loaded {len(devices)} devices")
    print("[*] Simulator started. Generating flows...")
    print("[*] Press Ctrl+C to stop\n")

    flow_count = 0

    try:
        while True:
            # Generate flows from each device
            for device in devices:
                flow = generate_flow(device)
                insert_flow(flow)
                flow_count += 1

            # Print progress every 10 flows
            if flow_count % 10 == 0:
                print(f"[+] Generated {flow_count} flows...")

            # Generate new flows every 0.5 seconds
            time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n[✓] Simulator stopped. Total flows: {flow_count}")


if __name__ == '__main__':
    main()
