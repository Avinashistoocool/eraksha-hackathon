import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
import time
import os

DB_PATH = 'data/flows.db'

def get_flows_for_training():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT bytes_sent, bytes_received, duration FROM flows ORDER BY timestamp DESC LIMIT 500')
    flows = cursor.fetchall()
    conn.close()
    return np.array(flows, dtype=float) if flows else None

def ensure_columns():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for col_name, col_def in [('checked', 'INTEGER DEFAULT 0'), ('anomaly', 'INTEGER DEFAULT 0'), ('anomaly_score', 'REAL DEFAULT 0')]:
        try:
            cursor.execute(f'ALTER TABLE flows ADD COLUMN {col_name} {col_def}')
            conn.commit()
        except:
            pass
    conn.close()

def get_unchecked_flows(batch_size=100):
    ensure_columns()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, bytes_sent, bytes_received, duration FROM flows WHERE checked = 0 ORDER BY id ASC LIMIT ?', (batch_size,))
    flows = cursor.fetchall()
    conn.close()
    return flows

def update_anomaly_score(flow_id, score, is_anomaly):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE flows SET anomaly_score = ?, anomaly = ?, checked = 1 WHERE id = ?', (float(score), int(is_anomaly), int(flow_id)))
    conn.commit()
    conn.close()

def train_model():
    print("[*] Training anomaly model...")
    for i in range(10):
        X = get_flows_for_training()
        if X is not None and len(X) >= 50:
            break
        print(f"[*] Waiting for flows... ({i + 1}/10)")
        time.sleep(1)
    if X is None or len(X) < 50:
        print("[!] Not enough flows to train")
        return None
    print(f"[*] Training on {len(X)} flows...")
    model = IsolationForest(contamination=0.1, n_estimators=50, random_state=42)
    model.fit(X)
    print("[✓] Model trained\n")
    return model

def detect_anomalies(model):
    print("[*] Starting detection loop...")
    print("[*] Press Ctrl+C to stop\n")
    try:
        while True:
            flows = get_unchecked_flows(batch_size=100)
            if not flows:
                print("[*] No new flows. Waiting...")
                time.sleep(2)
                continue
            anomaly_count = 0
            normal_count = 0
            for flow in flows:
                flow_id = int(flow[0])
                bytes_sent = float(flow[1])
                bytes_received = float(flow[2])
                duration = float(flow[3])
                X = np.array([[bytes_sent, bytes_received, duration]]).reshape(1, -1)
                prediction = model.predict(X)[0]
                score = model.decision_function(X)[0]
                normalized_score = 1 / (1 + np.exp(-score))
                is_anomaly = 1 if prediction == -1 else 0
                update_anomaly_score(flow_id, normalized_score, is_anomaly)
                if is_anomaly == 1:
                    anomaly_count += 1
                else:
                    normal_count += 1
            checked_total = anomaly_count + normal_count
            print(f"[+] Checked: {checked_total} flows | Anomalies: {anomaly_count} | Normal: {normal_count}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[✓] Detection stopped")

def main():
    print("[*] IoT Security - Anomaly Detection")
    print("[*] Using Machine Learning (Isolation Forest)\n")
    os.makedirs('data', exist_ok=True)
    model = train_model()
    if model is None:
        print("[!] Failed to train model")
        return
    detect_anomalies(model)

if __name__ == '__main__':
    main()
