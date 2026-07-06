"""
IoT Flow Generator - IMPROVED VERSION
Simulates IoT device traffic with clear output
"""

import sqlite3
import time
import random
import sys

DB_PATH = 'data/flows.db'


def create_tables():
    """Create database tables"""
    print("[*] Setting up database...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT,
            device_type TEXT,
            ip TEXT UNIQUE,
            port INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flows (
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
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    conn.commit()
    conn.close()
    print("[✓] Database tables ready\n")


def setup_test_devices():
    """Create simulated IoT devices"""
    devices = [
        ('DEV_CAM_1', 'Security Camera 1', 'Camera', '192.168.1.50'),
        ('DEV_CAM_2', 'Security Camera 2', 'Camera', '192.168.1.51'),
        ('DEV_LOCK_1', 'Smart Door Lock', 'Lock', '192.168.1.52'),
        ('DEV_LIGHT_1', 'Smart Light - Living Room', 'Light', '192.168.1.53'),
        ('DEV_LIGHT_2', 'Smart Light - Bedroom', 'Light', '192.168.1.54'),
        ('DEV_THERMOSTAT', 'Smart Thermostat', 'Climate', '192.168.1.55'),
        ('DEV_SPEAKER', 'Smart Speaker', 'Speaker', '192.168.1.56'),
        ('DEV_SENSOR_TEMP', 'Temperature Sensor', 'Sensor', '192.168.1.57'),
        ('DEV_SENSOR_MOTION', 'Motion Sensor', 'Sensor', '192.168.1.58'),
        ('DEV_GARAGE', 'Garage Door Opener', 'Actuator', '192.168.1.59'),
    ]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("[*] Creating 10 IoT devices...")
    for i, (device_id, name, device_type, ip) in enumerate(devices, 1):
        cursor.execute('''
            INSERT OR IGNORE INTO devices (id, name, device_type, ip, port)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, name, device_type, ip, 0))
        print(f"    [{i}/10] {name} ({ip})")

    conn.commit()
    conn.close()
    print("[✓] Devices created\n")


def generate_flows():
    """Generate continuous IoT network flows"""

    device_behaviors = {
        'DEV_CAM_1': {'bytes_range': (5000, 15000), 'protocol': 'TCP', 'frequency': 2},
        'DEV_CAM_2': {'bytes_range': (5000, 15000), 'protocol': 'TCP', 'frequency': 2},
        'DEV_LOCK_1': {'bytes_range': (100, 500), 'protocol': 'TCP', 'frequency': 0.5},
        'DEV_LIGHT_1': {'bytes_range': (50, 200), 'protocol': 'UDP', 'frequency': 5},
        'DEV_LIGHT_2': {'bytes_range': (50, 200), 'protocol': 'UDP', 'frequency': 5},
        'DEV_THERMOSTAT': {'bytes_range': (200, 800), 'protocol': 'TCP', 'frequency': 1},
        'DEV_SPEAKER': {'bytes_range': (1000, 5000), 'protocol': 'TCP', 'frequency': 3},
        'DEV_SENSOR_TEMP': {'bytes_range': (50, 150), 'protocol': 'UDP', 'frequency': 10},
        'DEV_SENSOR_MOTION': {'bytes_range': (30, 100), 'protocol': 'UDP', 'frequency': 8},
        'DEV_GARAGE': {'bytes_range': (100, 300), 'protocol': 'TCP', 'frequency': 0.2},
    }

    ips = {
        'DEV_CAM_1': '192.168.1.50',
        'DEV_CAM_2': '192.168.1.51',
        'DEV_LOCK_1': '192.168.1.52',
        'DEV_LIGHT_1': '192.168.1.53',
        'DEV_LIGHT_2': '192.168.1.54',
        'DEV_THERMOSTAT': '192.168.1.55',
        'DEV_SPEAKER': '192.168.1.56',
        'DEV_SENSOR_TEMP': '192.168.1.57',
        'DEV_SENSOR_MOTION': '192.168.1.58',
        'DEV_GARAGE': '192.168.1.59',
    }

    cloud_servers = ['8.8.8.8', '1.1.1.1', '52.123.45.67', '35.192.1.45', '20.102.33.44']

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    flow_count = 0
    anomaly_count = 0
    start_time = time.time()

    print("[*] Starting flow generation...")
    print("[*] Press Ctrl+C to stop\n")
    print("=" * 80)

    try:
        while True:
            for device_id, behavior in device_behaviors.items():
                for _ in range(int(behavior['frequency'])):
                    min_bytes, max_bytes = behavior['bytes_range']

                    # 5% chance of anomaly
                    if random.random() < 0.05:
                        bytes_sent = random.randint(20000, 50000)
                        anomaly_score = round(random.uniform(0.7, 1.0), 2)
                        anomaly = 1
                        status = "🚨 ANOMALY"
                        anomaly_count += 1
                    else:
                        bytes_sent = random.randint(min_bytes, max_bytes)
                        anomaly_score = round(random.uniform(0.0, 0.3), 2)
                        anomaly = 0
                        status = "✓ Normal"

                    src_ip = ips[device_id]
                    dst_ip = random.choice(cloud_servers)

                    cursor.execute('''
                        INSERT INTO flows 
                        (device_id, src_ip, dst_ip, src_port, dst_port, protocol,
                         bytes_sent, bytes_received, anomaly_score, anomaly)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device_id,
                        src_ip,
                        dst_ip,
                        random.randint(10000, 65535),
                        random.choice([53, 80, 443, 1883, 8080, 5683]),
                        behavior['protocol'],
                        bytes_sent,
                        random.randint(50, 1000),
                        anomaly_score,
                        anomaly
                    ))

                    flow_count += 1

                    # Print every 15 flows
                    if flow_count % 15 == 0:
                        conn.commit()
                        elapsed = time.time() - start_time
                        rate = flow_count / elapsed
                        device_name = cursor.execute('SELECT name FROM devices WHERE id=?', (device_id,)).fetchone()[0]

                        print(
                            f"[{flow_count:,} flows] [{anomaly_count} anomalies] | {device_name:30} | {src_ip}→{dst_ip} | {bytes_sent:6}B | {status} | {rate:.1f} flows/sec")
                        sys.stdout.flush()

            conn.commit()
            time.sleep(0.3)  # Control generation speed

    except KeyboardInterrupt:
        conn.commit()
        conn.close()
        elapsed = time.time() - start_time
        print("\n" + "=" * 80)
        print(f"\n[✓] STOPPED")
        print(f"[✓] Generated: {flow_count:,} total flows")
        print(f"[✓] Anomalies: {anomaly_count} ({anomaly_count / flow_count * 100:.1f}%)")
        print(f"[✓] Time: {elapsed:.1f} seconds")
        print(f"[✓] Rate: {flow_count / elapsed:.1f} flows/second")
        print(f"\n[→] Dashboard is ready at: http://localhost:5000")
        print(f"[→] Make sure server.py is running in another terminal!\n")


if __name__ == '__main__':
    try:
        create_tables()
        setup_test_devices()
        generate_flows()
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback

        traceback.print_exc()