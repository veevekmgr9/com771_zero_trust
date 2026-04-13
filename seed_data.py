import sqlite3
from werkzeug.security import generate_password_hash

users = [
    ("admin", generate_password_hash("admin123"), "Admin", 1, "ADMIN-DEVICE-001", "active"),
    ("doctor1", generate_password_hash("doctor123"), "Doctor", 1, "DOC-DEVICE-001", "active"),
    ("nurse1", generate_password_hash("nurse123"), "Nurse", 1, "NURSE-DEVICE-001", "active"),
    ("patient1", generate_password_hash("patient123"), "Patient", 1, "PATIENT-DEVICE-001", "active"),
]

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

for user in users:
    try:
        cursor.execute("""
            INSERT INTO users (username, password, role, mfa_enabled, device_id, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, user)
    except sqlite3.IntegrityError:
        pass

conn.commit()
conn.close()

print("Sample users inserted successfully.")