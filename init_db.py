import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    mfa_enabled INTEGER DEFAULT 1,
    device_id TEXT,
    status TEXT DEFAULT 'active'
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT NOT NULL,
    age INTEGER,
    disease TEXT,
    diagnosis_encrypted TEXT,
    doctor_assigned TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT NOT NULL,
    device_id TEXT UNIQUE NOT NULL,
    device_serial_number TEXT,
    device_status TEXT NOT NULL,
    owner_role TEXT,
    device_type TEXT,
    can_access_data INTEGER DEFAULT 0,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS device_patient_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    patient_id INTEGER NOT NULL,
    assigned_by TEXT,
    access_type TEXT NOT NULL,
    assignment_status TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS device_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    patient_id INTEGER NOT NULL,
    heart_rate REAL,
    temperature REAL,
    oxygen_level REAL,
    reading_status TEXT NOT NULL,
    notes TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS trusted_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    description TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    role TEXT,
    module_name TEXT,
    device_name TEXT,
    ip_address TEXT,
    requested_action TEXT,
    request_count INTEGER,
    user_input TEXT,
    attack_type TEXT,
    decision TEXT,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS access_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT,
    module_name TEXT,
    action TEXT,
    requires_mfa INTEGER DEFAULT 1,
    requires_trusted_device INTEGER DEFAULT 1,
    requires_trusted_ip INTEGER DEFAULT 1
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS download_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    patient_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

print("Database created successfully.")