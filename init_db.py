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
    device_name TEXT,
    device_id TEXT UNIQUE,
    device_serial_number TEXT,
    device_status TEXT,
    owner_role TEXT
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

conn.commit()
conn.close()

print("Database created successfully.")