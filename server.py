import sqlite3
from flask import Flask, render_template_string, jsonify
import json
import os
print("SERVER CWD:", os.getcwd())
print("DB EXISTS:", os.path.exists("dataflows.db"))


app = Flask(__name__)
DB_PATH = "devices.db"


# --- DATABASE SETUP ---
def init_db():
    """Initializes the DB with WAL mode to prevent locking."""
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")  # Crucial for concurrency
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY, 
                mac TEXT,
                vendor TEXT,
                last_seen TEXT
            )
        """)


# --- FLASK ROUTES ---
@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Sniffer Dashboard</title>
        <meta http-equiv="refresh" content="5"> <!-- Auto-refresh every 5s -->
        <style>
            body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #333; padding: 10px; text-align: left; }
            th { background: #222; color: #fff; }
            tr:nth-child(even) { background: #1a1a1a; }
            .status { font-size: 1.2em; margin-bottom: 10px; }
        </style>
    </head>
    <body>
        <h1>LIVE NETWORK SNIFFER</h1>
        <div class="status" id="status">Loading data...</div>
        <table id="deviceTable">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Vendor/Info</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>

        <script>
            async function fetchData() {
                try {
                    const res = await fetch('/data');
                    const data = await res.json();
                    const tbody = document.querySelector('#deviceTable tbody');
                    tbody.innerHTML = '';

                    data.forEach(dev => {
                        const row = `<tr>
                            <td>${dev.ip}</td>
                            <td>${dev.mac}</td>
                            <td>${dev.vendor}</td>
                            <td>${dev.last_seen}</td>
                        </tr>`;
                        tbody.innerHTML += row;
                    });
                    document.getElementById('status').innerText = `Devices Online: ${data.length}`;
                } catch (e) {
                    console.error("Fetch error:", e);
                }
            }
            fetchData();
            setInterval(fetchData, 2000); // Live update via API
        </script>
    </body>
    </html>
    ''')


@app.route('/data')
def get_data():
    try:
        # Connect with timeout to avoid locking
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            rows = [dict(row) for row in cursor.fetchall()]
            return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    init_db()  # Run DB setup once on start
    app.run(host='0.0.0.0', port=5000, debug=True)
