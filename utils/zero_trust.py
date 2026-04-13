from utils.db import get_db_connection

# Utility functions for check trusted ips
def is_trusted_ip(ip_address):
    if not ip_address:
        return False

    conn = get_db_connection()
    ip = conn.execute("""
        SELECT * FROM trusted_ips
        WHERE ip_address = ?
    """, (ip_address,)).fetchone()
    conn.close()

    return ip is not None

# Utility functions for get device by id
def get_device_by_id(device_id):
    if not device_id:
        return None

    conn = get_db_connection()
    device = conn.execute("""
        SELECT * FROM trusted_devices
        WHERE device_id = ?
    """, (device_id,)).fetchone()
    conn.close()

    return device

# Utility functions for check trusted devices
def is_trusted_device(device_id):
    device = get_device_by_id(device_id)
    return device is not None and device["device_status"] == "active"

# Utility function to update last seen timestamp for a device
def update_device_last_seen(device_id):
    conn = get_db_connection()
    conn.execute("""
        UPDATE trusted_devices
        SET last_seen = CURRENT_TIMESTAMP
        WHERE device_id = ?
    """, (device_id,))
    conn.commit()
    conn.close()

# Utility function to get access policy for a role, module, and action
def get_access_policy(role, module_name, action):
    conn = get_db_connection()
    policy = conn.execute("""
        SELECT * FROM access_policies
        WHERE role = ? AND module_name = ? AND action = ?
    """, (role, module_name, action)).fetchone()
    conn.close()

    return policy

# Main function to perform Zero Trust checks
def zero_trust_check(module_name, action, session_data, ip_address, device_id):
    username = session_data.get("username")
    role = session_data.get("role")
    mfa_verified = session_data.get("mfa_verified", False)

    if not username:
        return False, "User not logged in"

    if not role:
        return False, "User role missing"

    policy = get_access_policy(role, module_name, action)
    if not policy:
        return False, "No access policy found"

    if policy["requires_mfa"] and not mfa_verified:
        return False, "MFA not verified"

    if policy["requires_trusted_device"] and not is_trusted_device(device_id):
        return False, "Untrusted or blocked device"

    if policy["requires_trusted_ip"] and not is_trusted_ip(ip_address):
        return False, "Untrusted IP address"

    return True, "Access granted"

# Additional utility function to check if a device has an active assignment for a patient and action
def has_active_device_assignment(device_id, patient_id, access_type="read"):
    conn = get_db_connection()
    assignment = conn.execute("""
        SELECT * FROM device_patient_assignments
        WHERE device_id = ?
          AND patient_id = ?
          AND assignment_status = 'active'
          AND (access_type = ? OR access_type = 'read_write')
    """, (device_id, patient_id, access_type)).fetchone()
    conn.close()

    return assignment is not None

# Main function to verify IoT device access based on device status, trusted IP, and active assignments
def verify_iot_device_access(device_id, patient_id, ip_address, requested_action="read"):
    device = get_device_by_id(device_id)

    if not device:
        return False, "Unknown IoT device"

    if device["device_status"] != "active":
        return False, "IoT device is blocked or inactive"

    if int(device["can_access_data"]) != 1:
        return False, "IoT device is not permitted to access system data"

    if not is_trusted_ip(ip_address):
        return False, "IoT request came from untrusted IP"

    if not has_active_device_assignment(device_id, patient_id, requested_action):
        return False, "No active device assignment for this patient and action"

    update_device_last_seen(device_id)
    return True, "IoT device access granted"