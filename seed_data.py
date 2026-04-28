import sqlite3
from werkzeug.security import generate_password_hash

users = [
    ("admin", generate_password_hash("admin123"), "Admin", 1, "ADMIN-DEVICE-001", "active"),
    ("doctor1", generate_password_hash("doctor123"), "Doctor", 1, "DOC-DEVICE-001", "active"),
    ("nurse1", generate_password_hash("nurse123"), "Nurse", 1, "NURSE-DEVICE-001", "active"),
    ("patient1", generate_password_hash("patient123"), "Patient", 1, "PATIENT-DEVICE-001", "active"),
]

patients = [
    ("John Cena", 45, "Hypertension", "Encrypted Diagnosis Placeholder", "doctor1"),
    ("Lancelot", 32, "Diabetes", "Encrypted Diagnosis Placeholder", "doctor1"),
    ("Tanjiro Kamado", 60, "Asthma", "Encrypted Diagnosis Placeholder", "doctor1"),
]

trusted_devices = [
    ("Admin Laptop", "ADMIN-DEVICE-001", "SERIAL-ADMIN-001", "active", "Admin", "Laptop", 1),
    ("Doctor Laptop", "DOC-DEVICE-001", "SERIAL-DOC-001", "active", "Doctor", "Laptop", 1),
    ("Nurse Tablet", "NURSE-DEVICE-001", "SERIAL-NURSE-001", "active", "Nurse", "Tablet", 1),
    ("Patient Phone", "PATIENT-DEVICE-001", "SERIAL-PATIENT-001", "active", "Patient", "Phone", 0),

    ("Heart Rate Monitor", "IOT-HEART-001", "SERIAL-IOT-HR-001", "active", "IoT", "Heart Monitor", 1),
    ("Oxygen Monitor", "IOT-OXY-001", "SERIAL-IOT-OXY-001", "active", "IoT", "Oxygen Sensor", 1),
    ("Temperature Sensor", "IOT-TEMP-001", "SERIAL-IOT-TEMP-001", "blocked", "IoT", "Temperature Sensor", 1),
]

device_patient_assignments = [
    ("IOT-HEART-001", 1, "admin", "read_write", "active", None),
    ("IOT-OXY-001", 1, "admin", "read", "active", None),
    ("IOT-HEART-001", 2, "admin", "read", "ended", "2026-04-01 10:00:00"),
    ("IOT-TEMP-001", 2, "admin", "read_write", "active", None),
]

trusted_ips = [
    ("127.0.0.1", "Localhost trusted for testing"),
]

access_policies = [
    ("Admin", "Dashboard", "View", 1, 1, 1),
    ("Doctor", "Dashboard", "View", 1, 1, 1),
    ("Nurse", "Dashboard", "View", 1, 1, 1),
    ("Patient", "Dashboard", "View", 1, 1, 1),
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

for patient in patients:
    cursor.execute("""
        SELECT id FROM patients WHERE patient_name=? AND age=?
    """, (patient[0], patient[1]))
    existing = cursor.fetchone()
    if not existing:
        cursor.execute("""
            INSERT INTO patients (patient_name, age, disease, diagnosis_encrypted, doctor_assigned)
            VALUES (?, ?, ?, ?, ?)
        """, patient)

for device in trusted_devices:
    try:
        cursor.execute("""
            INSERT INTO trusted_devices
            (device_name, device_id, device_serial_number, device_status, owner_role, device_type, can_access_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, device)
    except sqlite3.IntegrityError:
        pass

for assignment in device_patient_assignments:
    cursor.execute("""
        SELECT id FROM device_patient_assignments
        WHERE device_id=? AND patient_id=? AND access_type=? AND assignment_status=?
    """, (assignment[0], assignment[1], assignment[3], assignment[4]))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO device_patient_assignments
            (device_id, patient_id, assigned_by, access_type, assignment_status, end_time)
            VALUES (?, ?, ?, ?, ?, ?)
        """, assignment)

for ip in trusted_ips:
    try:
        cursor.execute("""
            INSERT INTO trusted_ips (ip_address, description)
            VALUES (?, ?)
        """, ip)
    except sqlite3.IntegrityError:
        pass

for policy in access_policies:
    cursor.execute("""
        SELECT id FROM access_policies
        WHERE role=? AND module_name=? AND action=?
    """, (policy[0], policy[1], policy[2]))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO access_policies
            (role, module_name, action, requires_mfa, requires_trusted_device, requires_trusted_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        """, policy)

conn.commit()
conn.close()

print("Sample data inserted successfully.")