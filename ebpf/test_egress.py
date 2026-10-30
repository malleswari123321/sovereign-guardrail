import socket
import errno

def test_connection(ip, description):
    print(f"\n[TEST] Testing egress to {description} ({ip}:80)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, 80))
        print(f"✅ ALLOWED: Successfully connected to {ip}")
        s.close()
    except socket.error as e:
        err_code = e.errno
        if err_code in [errno.EPERM, errno.EACCES, errno.ECONNREFUSED]:
            print(f"🛡️ BLOCKED BY eBPF KERNEL FILTER: Packet dropped for {ip} (Error code: {err_code})")
        else:
            print(f"⏱️ Network timeout / unreachable (Standard socket behavior for {ip}): {e}")

if __name__ == "__main__":
    print("=== Sovereign eBPF Egress Guardrail Verification ===")
    test_connection("192.168.1.100", "Approved Sovereign IP")
    test_connection("8.8.8.8", "Unauthorized Foreign IP")
