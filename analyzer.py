import re
from collections import defaultdict

LOG_FILE = "auth.log"
THRESHOLD = 3

failed_attempts = defaultdict(int)

with open(LOG_FILE, "r") as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_attempts[ip] += 1

print("=== RELATÓRIO DE SEGURANÇA ===\n")

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(f"[ALERTA] Possível ataque de força bruta detectado!")
        print(f"IP suspeito: {ip}")
        print(f"Tentativas falhas: {count}\n")
    else:
        print(f"[INFO] IP {ip} teve {count} falhas.")


