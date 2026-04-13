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

app = Flask(__name__)
app.secret_key = "QLAKSIBjksandjkabhOIWHOI1289192837@@#(@(*#(@Q!!@_+_+)))"


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
    if "username" not in session:
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
    if "username" not in session:
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


@app.route("/iot_access", methods=["GET", "POST"])
def iot_access():
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


@app.route("/submit_reading", methods=["GET", "POST"])
def submit_reading():
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

        decision = "ALLOW" if reading_status == "normal" else "ALLOW"
        attack_type = "None" if reading_status == "normal" else "Suspicious IoT Reading"

        log_security_event(
            "DEVICE",
            "IoT",
            "Submit Reading",
            device_id,
            request.remote_addr,
            "WRITE Reading",
            1,
            f"patient_id={patient_id}",
            attack_type,
            decision,
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
    if "username" not in session:
        return redirect(url_for("login"))

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