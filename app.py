#app.secret_key = "QLAKSIBjksandjkabhOIWHOI1289192837@@#(@(*#(@Q!!@_+_+)))"
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash

from utils.db import get_db_connection
from utils.zero_trust import (
    zero_trust_check,
    verify_iot_device_access,
    detect_abnormal_readings
)
from utils.logger import log_security_event
from utils.input_detection import inspect_input

app = Flask(__name__)
app.secret_key = "change_this_to_a_long_random_secret_key"


def require_login():
    return "username" in session

def require_role(*allowed_roles):
    return session.get("role") in allowed_roles

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND status = 'active'",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["mfa_verified"] = False
            session["device_id"] = user["device_id"]

            log_security_event(
                user["username"],
                user["role"],
                "Login",
                user["device_id"],
                request.remote_addr,
                "Login Attempt",
                1,
                "",
                "None",
                "ALLOW",
                "Username and password verified"
            )

            return redirect(url_for("verify_otp"))
        else:
            log_security_event(
                username if username else "Unknown",
                "Unknown",
                "Login",
                "Unknown",
                request.remote_addr,
                "Login Attempt",
                1,
                username,
                "Invalid Credentials",
                "DENY",
                "Invalid username or password"
            )
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if not require_login():
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if otp == "123456":
            session["mfa_verified"] = True

            log_security_event(
                session.get("username"),
                session.get("role"),
                "MFA",
                session.get("device_id"),
                request.remote_addr,
                "OTP Verification",
                1,
                otp,
                "None",
                "ALLOW",
                "OTP verified successfully"
            )

            flash("OTP verified successfully.", "info")
            return redirect(url_for("dashboard"))
        else:
            log_security_event(
                session.get("username"),
                session.get("role"),
                "MFA",
                session.get("device_id"),
                request.remote_addr,
                "OTP Verification",
                1,
                otp,
                "Invalid OTP",
                "DENY",
                "Incorrect OTP entered"
            )
            flash("Invalid OTP. Please try again.", "danger")

    return render_template("verify_otp.html")


@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))

    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        log_security_event(
            session.get("username"),
            session.get("role"),
            "Dashboard",
            session.get("device_id"),
            request.remote_addr,
            "View",
            1,
            "",
            "Access Control",
            "DENY",
            message
        )
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("login"))

    log_security_event(
        session.get("username"),
        session.get("role"),
        "Dashboard",
        session.get("device_id"),
        request.remote_addr,
        "View",
        1,
        "",
        "None",
        "ALLOW",
        "Dashboard access granted"
    )

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        device_id=session.get("device_id"),
        mfa_verified=session.get("mfa_verified"),
        ip_address=request.remote_addr
    )

@app.route("/admin")
def admin_panel():
    if not require_login():
        return redirect(url_for("login"))

    if not require_role("Admin"):
        flash("Access denied. Only administrators can access the admin panel.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    stats = {
        "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "devices": conn.execute("SELECT COUNT(*) FROM trusted_devices").fetchone()[0],
        "active_devices": conn.execute("SELECT COUNT(*) FROM trusted_devices WHERE device_status='active'").fetchone()[0],
        "blocked_devices": conn.execute("SELECT COUNT(*) FROM trusted_devices WHERE device_status='blocked'").fetchone()[0],
        "readings": conn.execute("SELECT COUNT(*) FROM device_readings").fetchone()[0],
    }

    devices = conn.execute("SELECT * FROM trusted_devices").fetchall()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    ips = conn.execute("SELECT * FROM trusted_ips").fetchall()

    assignments = conn.execute("""
        SELECT dpa.*, p.patient_name
        FROM device_patient_assignments dpa
        JOIN patients p ON dpa.patient_id = p.id
        ORDER BY dpa.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        stats=stats,
        devices=devices,
        patients=patients,
        ips=ips,
        assignments=assignments
    )
@app.route("/assignments")
def assignments():
    if not require_login():
        return redirect(url_for("login"))

    if not require_role("Admin", "Doctor"):
        flash("Access denied. Only administrators and doctors can assign devices.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    assignments = conn.execute("""
        SELECT dpa.*, td.device_name, p.patient_name
        FROM device_patient_assignments dpa
        JOIN trusted_devices td ON dpa.device_id = td.device_id
        JOIN patients p ON dpa.patient_id = p.id
        ORDER BY dpa.start_time DESC
    """).fetchall()
    
    devices = conn.execute("SELECT * FROM trusted_devices").fetchall()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()

    return render_template("assign_patients.html", assignments=assignments, devices=devices, patients=patients)

@app.route("/patients")
def patients():
    if not require_login():
        return redirect(url_for("login"))

    if not require_role("Admin", "Doctor", "Nurse"):
        flash("Access denied. Only administrators, doctors, and nurses can view patient records.", "danger")
        return redirect(url_for("dashboard"))

    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        log_security_event(
            session.get("username"),
            session.get("role"),
            "Patients",
            session.get("device_id"),
            request.remote_addr,
            "View Patients",
            1,
            "",
            "Access Control",
            "DENY",
            message
        )
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    all_patients = conn.execute("SELECT * FROM patients ORDER BY id ASC").fetchall()
    conn.close()

    log_security_event(
        session.get("username"),
        session.get("role"),
        "Patients",
        session.get("device_id"),
        request.remote_addr,
        "View Patients",
        1,
        "",
        "None",
        "ALLOW",
        "Patient records viewed successfully"
    )

    return render_template(
        "patients.html",
        patients=all_patients,
        search_results=None,
        error=None
    )


@app.route("/search_patient", methods=["POST"])
def search_patient():
    if not require_login():
        return redirect(url_for("login"))
    
    if not require_role("Admin", "Doctor", "Nurse"):
        flash("Access denied. Only authorized users can search for patients.", "danger")
        return redirect(url_for("dashboard"))

    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        log_security_event(
            session.get("username"),
            session.get("role"),
            "Patients",
            session.get("device_id"),
            request.remote_addr,
            "Search Patient",
            1,
            "",
            "Access Control",
            "DENY",
            message
        )
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("dashboard"))

    search_query = request.form.get("search_query", "").strip()

    input_ok, attack_type = inspect_input(search_query)

    conn = get_db_connection()
    all_patients = conn.execute("SELECT * FROM patients ORDER BY id ASC").fetchall()

    if not input_ok:
        log_security_event(
            session.get("username"),
            session.get("role"),
            "Patients",
            session.get("device_id"),
            request.remote_addr,
            "Search Patient",
            1,
            search_query,
            attack_type,
            "DENY",
            f"{attack_type} detected in search input"
        )
        conn.close()

        return render_template(
            "patients.html",
            patients=all_patients,
            search_results=None,
            error=f"{attack_type} detected. Request blocked."
        )

    search_results = conn.execute("""
        SELECT * FROM patients
        WHERE patient_name LIKE ? OR id LIKE ? OR disease LIKE ?
        ORDER BY id ASC
    """, (
        f"%{search_query}%",
        f"%{search_query}%",
        f"%{search_query}%"
    )).fetchall()
    conn.close()

    log_security_event(
        session.get("username"),
        session.get("role"),
        "Patients",
        session.get("device_id"),
        request.remote_addr,
        "Search Patient",
        1,
        search_query,
        "None",
        "ALLOW",
        "Patient search completed successfully"
    )

    return render_template(
        "patients.html",
        patients=all_patients,
        search_results=search_results,
        error=None
    )


@app.route("/iot_access", methods=["GET", "POST"])
def iot_access():
    if "username" not in session:
        return redirect(url_for("login"))
    
    if not require_role("Admin", "Doctor", "Nurse"):
        flash("Access denied. Only authorized users can access IoT devices.", "danger")
        return redirect(url_for("dashboard"))

    result = None

    if request.method == "POST":
        device_id = request.form.get("device_id", "").strip()
        patient_id = request.form.get("patient_id", "").strip()
        requested_action = request.form.get("requested_action", "read").strip()

        allowed, message = verify_iot_device_access(
            device_id=device_id,
            patient_id=patient_id,
            ip_address=request.remote_addr,
            requested_action=requested_action
        )

        if allowed:
            log_security_event(
                "DEVICE",
                "IoT",
                "IoT Access",
                device_id,
                request.remote_addr,
                f"{requested_action.upper()} Patient Data",
                1,
                patient_id,
                "None",
                "ALLOW",
                message
            )

            conn = get_db_connection()
            patient = conn.execute(
                "SELECT * FROM patients WHERE id = ?",
                (patient_id,)
            ).fetchone()
            conn.close()

            if patient:
                result = {
                    "status": "ALLOW",
                    "message": message,
                    "patient_name": patient["patient_name"],
                    "disease": patient["disease"],
                    "doctor_assigned": patient["doctor_assigned"]
                }
            else:
                result = {
                    "status": "DENY",
                    "message": "Patient not found"
                }
        else:
            log_security_event(
                "DEVICE",
                "IoT",
                "IoT Access",
                device_id if device_id else "Unknown Device",
                request.remote_addr,
                f"{requested_action.upper()} Patient Data",
                1,
                patient_id,
                "IoT Access Violation",
                "DENY",
                message
            )

            result = {
                "status": "DENY",
                "message": message
            }

    return render_template("iot_access.html", result=result)

@app.route("/add_device", methods=["POST"])
def add_device():
    if not require_login() or not require_role("Admin"):
        return redirect(url_for("dashboard"))

    name = request.form["device_name"].strip()
    device_id = request.form["device_id"].strip()
    device_type = request.form["device_type"].strip()

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM trusted_devices WHERE device_id = ?",
        (device_id,)
    ).fetchone()

    if existing:
        conn.close()
        flash("Device ID already exists.", "danger")
        return redirect(url_for("admin_panel"))

    conn.execute("""
        INSERT INTO trusted_devices
        (device_name, device_id, device_status, owner_role, device_type, can_access_data)
        VALUES (?, ?, 'active', 'IoT', ?, 1)
    """, (name, device_id, device_type))
    conn.commit()
    conn.close()

    flash("Device added successfully.", "info")
    return redirect(url_for("admin_panel"))

@app.route("/toggle_device/<device_id>")
def toggle_device(device_id):
    if not require_role("Admin"):
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    device = conn.execute("""
        SELECT device_status FROM trusted_devices WHERE device_id=?
    """, (device_id,)).fetchone()

    new_status = "blocked" if device["device_status"] == "active" else "active"

    conn.execute("""
        UPDATE trusted_devices SET device_status=? WHERE device_id=?
    """, (new_status, device_id))

    conn.commit()
    conn.close()

    return redirect(url_for("admin_panel"))

@app.route("/assign_device", methods=["POST"])
def assign_device():
    if not require_login() or not require_role("Admin"):
        return redirect(url_for("dashboard"))

    device_id = request.form["device_id"].strip()
    patient_id = request.form["patient_id"].strip()
    access_type = request.form["access_type"].strip()

    conn = get_db_connection()

    existing = conn.execute("""
        SELECT id FROM device_patient_assignments
        WHERE device_id = ?
          AND patient_id = ?
          AND access_type = ?
          AND assignment_status = 'active'
    """, (device_id, patient_id, access_type)).fetchone()

    if existing:
        conn.close()
        flash("This active assignment already exists.", "danger")
        return redirect(url_for("admin_panel"))

    conn.execute("""
        INSERT INTO device_patient_assignments
        (device_id, patient_id, assigned_by, access_type, assignment_status)
        VALUES (?, ?, ?, ?, 'active')
    """, (device_id, patient_id, session["username"], access_type))

    conn.commit()
    conn.close()

    flash("Device assigned successfully.", "info")
    return redirect(url_for("assignments"))

@app.route("/add_ip", methods=["POST"])
def add_ip():
    if not require_login() or not require_role("Admin"):
        return redirect(url_for("dashboard"))

    ip = request.form["ip"].strip()

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM trusted_ips WHERE ip_address = ?",
        (ip,)
    ).fetchone()

    if existing:
        conn.close()
        flash("Trusted IP already exists.", "danger")
        return redirect(url_for("admin_panel"))

    conn.execute("INSERT INTO trusted_ips (ip_address) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

    flash("Trusted IP added successfully.", "info")
    return redirect(url_for("admin_panel"))

@app.route("/submit_reading", methods=["GET", "POST"])
def submit_reading():
    if not require_login():
        return redirect(url_for("login"))
    
    if not require_role("Admin", "Doctor", "Nurse"):
        flash("Access denied. Only authorized users can submit readings.", "danger")
        return redirect(url_for("dashboard"))

    result = None

    if request.method == "POST":
        device_id = request.form.get("device_id", "").strip()
        patient_id = request.form.get("patient_id", "").strip()
        heart_rate_raw = request.form.get("heart_rate", "").strip()
        temperature_raw = request.form.get("temperature", "").strip()
        oxygen_raw = request.form.get("oxygen_level", "").strip()

        try:
            heart_rate = float(heart_rate_raw) if heart_rate_raw else None
            temperature = float(temperature_raw) if temperature_raw else None
            oxygen_level = float(oxygen_raw) if oxygen_raw else None
        except ValueError:
            result = {
                "status": "DENY",
                "message": "Invalid numeric input in reading values"
            }
            return render_template("submit_reading.html", result=result)

        allowed, message = verify_iot_device_access(
            device_id=device_id,
            patient_id=patient_id,
            ip_address=request.remote_addr,
            requested_action="write"
        )

        if not allowed:
            log_security_event(
                "DEVICE",
                "IoT",
                "Submit Reading",
                device_id if device_id else "Unknown Device",
                request.remote_addr,
                "WRITE Reading",
                1,
                f"patient_id={patient_id}",
                "IoT Write Violation",
                "DENY",
                message
            )

            result = {
                "status": "DENY",
                "message": message
            }
            return render_template("submit_reading.html", result=result)

        reading_status, notes = detect_abnormal_readings(
            heart_rate=heart_rate,
            temperature=temperature,
            oxygen_level=oxygen_level
        )

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO device_readings
            (device_id, patient_id, heart_rate, temperature, oxygen_level, reading_status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            patient_id,
            heart_rate,
            temperature,
            oxygen_level,
            reading_status,
            notes
        ))
        conn.commit()
        conn.close()

        log_security_event(
            "DEVICE",
            "IoT",
            "Submit Reading",
            device_id,
            request.remote_addr,
            "WRITE Reading",
            1,
            f"patient_id={patient_id}",
            "None" if reading_status == "normal" else "Suspicious IoT Reading",
            "ALLOW",
            notes
        )

        result = {
            "status": "ALLOW",
            "message": "Reading submitted successfully",
            "reading_status": reading_status,
            "notes": notes
        }

    return render_template("submit_reading.html", result=result)


@app.route("/device_readings")
def device_readings():
    if not require_login():
        return redirect(url_for("login"))
    
    if not require_role("Admin", "Doctor", "Nurse"):
        flash("Access denied. Only authorized users can view device readings.", "danger")
        return redirect(url_for("dashboard"))

    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    readings = conn.execute("""
        SELECT dr.*, p.patient_name
        FROM device_readings dr
        JOIN patients p ON dr.patient_id = p.id
        ORDER BY dr.timestamp DESC
    """).fetchall()
    conn.close()

    return render_template("device_readings.html", readings=readings)


@app.route("/security_logs")
def security_logs():
    if not require_login():
        return redirect(url_for("login"))

    if not require_role("Admin"):
        flash("Access denied. Only administrators can view security logs.", "danger")
        return redirect(url_for("dashboard"))

    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    logs = conn.execute("""
        SELECT * FROM security_logs
        ORDER BY timestamp DESC, id DESC
    """).fetchall()
    conn.close()

    return render_template("security_logs.html", logs=logs)

@app.route("/analytics")
def analytics():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Access denied. Admin only.", "danger")
        return redirect(url_for("dashboard"))
    
    allowed, message = zero_trust_check(
        "Dashboard",
        "View",
        session,
        request.remote_addr,
        session.get("device_id")
    )

    if not allowed:
        flash(f"Access denied: {message}", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    total_logs = conn.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
    allow_logs = conn.execute("SELECT COUNT(*) FROM security_logs WHERE decision='ALLOW'").fetchone()[0]
    deny_logs = conn.execute("SELECT COUNT(*) FROM security_logs WHERE decision='DENY'").fetchone()[0]

    total_readings = conn.execute("SELECT COUNT(*) FROM device_readings").fetchone()[0]
    normal_readings = conn.execute("SELECT COUNT(*) FROM device_readings WHERE reading_status='normal'").fetchone()[0]
    suspicious_readings = conn.execute("SELECT COUNT(*) FROM device_readings WHERE reading_status='suspicious'").fetchone()[0]

    attack_rows = conn.execute("""
        SELECT attack_type, COUNT(*) as total
        FROM security_logs
        WHERE attack_type IS NOT NULL
          AND attack_type != 'None'
        GROUP BY attack_type
        ORDER BY total DESC
    """).fetchall()

    reading_rows = conn.execute("""
        SELECT device_id, COUNT(*) as total
        FROM device_readings
        GROUP BY device_id
        ORDER BY total DESC
    """).fetchall()

    conn.close()

    attack_labels = [row["attack_type"] for row in attack_rows]
    attack_counts = [row["total"] for row in attack_rows]

    device_labels = [row["device_id"] for row in reading_rows]
    device_counts = [row["total"] for row in reading_rows]

    stats = {
        "total_logs": total_logs,
        "allow_logs": allow_logs,
        "deny_logs": deny_logs,
        "total_readings": total_readings,
        "normal_readings": normal_readings,
        "suspicious_readings": suspicious_readings,
    }

    return render_template(
        "analytics.html",
        stats=stats,
        attack_labels=attack_labels,
        attack_counts=attack_counts,
        device_labels=device_labels,
        device_counts=device_counts,
    )

@app.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    role = session.get("role", "Unknown")
    device_id = session.get("device_id", "Unknown")

    log_security_event(
        username,
        role,
        "Logout",
        device_id,
        request.remote_addr,
        "Logout",
        1,
        "",
        "None",
        "ALLOW",
        "User logged out"
    )

    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)