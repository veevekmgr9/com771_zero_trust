from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash

from utils.db import get_db_connection
from utils.zero_trust import zero_trust_check, verify_iot_device_access
from utils.logger import log_security_event

app = Flask(__name__)
app.secret_key = "change_this_to_a_long_random_secret_key"

# Route for home page
@app.route("/")
def home():
    return redirect(url_for("login"))

# Route for login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # get user from database
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND status = 'active'",
            (username,)
        ).fetchone()
        conn.close()

        # validate user credentials
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["mfa_verified"] = False
            session["device_id"] = user["device_id"]

            # Log successful login attempt
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

# Route for OTP verification page   
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

# Route for dashboard page with Zero Trust checks
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

# Route for IoT device access simulation
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

# Route for logout
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