from utils.db import get_db_connection

# Utility function to log security events
def log_security_event(username, role, module_name, device_name, ip_address,
                       requested_action, request_count, user_input,
                       attack_type, decision, reason):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO security_logs
        (username, role, module_name, device_name, ip_address,
         requested_action, request_count, user_input, attack_type,
         decision, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, role, module_name, device_name, ip_address,
        requested_action, request_count, user_input,
        attack_type, decision, reason
    ))
    conn.commit()
    conn.close()