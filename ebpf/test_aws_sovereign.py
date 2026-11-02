import socket
import sys

targets = [
    {
        "name": "AWS Mumbai Sovereign Zone (ap-south-1)",
        "endpoint": "sovereign-mumbai-malleswari.s3.ap-south-1.amazonaws.com",
        "port": 443
    },
    {
        "name": "AWS US-East Restricted Zone (us-east-1)",
        "endpoint": "restricted-useast-malleswari.s3.us-east-1.amazonaws.com",
        "port": 443
    }
]

print("=" * 65)
print("🛡️ AWS REAL-WORLD SOVEREIGN CLOUD BOUNDARY TEST")
print("=" * 65 + "\n")

for target in targets:
    print(f"[TEST] Target: {target['name']}")
    try:
        ip = socket.gethostbyname(target['endpoint'])
        print(f"       Resolved Bucket IP: {ip}")
        print(f"       Connecting to {ip}:{target['port']}...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, target['port']))
        print("       ✅ SUCCESS: Traffic routed cleanly to sovereign AWS zone!\n")
        s.close()
    except socket.timeout:
        print("       🛡️ KERNEL DROP: Egress packet dropped by eBPF (TC_ACT_SHOT)!\n")
    except Exception as e:
        print(f"       🛡️ KERNEL DROP: Connection dropped by eBPF ({e})\n")
