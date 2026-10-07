import random
import time
import requests

URL = "http://127.0.0.1:8000/logs"

USUARIOS = ["alexander", "admin", "root", "cony", "mituel", "test"]
IPS_NORMALES = ["192.168.1.10", "192.168.1.22", "192.168.1.35", "10.0.0.5"]
IP_ATACANTE = "45.33.12.9"
IP_BLACKLIST = "6.6.6.6"

def enviar(ip, tipo, usuario=None, mensaje=None):
    data = {
        "source_ip": ip,
        "event_type": tipo,
        "username": usuario,
        "message": mensaje,
    }
    r = requests.post(URL, json=data)
    print(r.status_code, ip, tipo, usuario)

print("trafico normal")
for _ in range(10):
    ip = random.choice(IPS_NORMALES)
    user = random.choice(USUARIOS)
    enviar(ip, "login_ok", user, "login exitoso")
    time.sleep(0.2)

print("fuerza bruta")
for i in range(8):
    user = random.choice(["admin", "root", "test"])
    enviar(IP_ATACANTE, "login_failed", user, f"intento {i+1} fallido")
    time.sleep(0.3)

print("ip blacklist")
enviar(IP_BLACKLIST, "login_ok", "admin", "acceso desde ip sospechosa")

print("spraying ")
for user in ["admin", "root", "cony", "mituel", "test"]:
    enviar("77.88.55.1", "login_failed", user, "intento fallido")
    time.sleep(0.2)

print("listo, revisa http://127.0.0.1:8000/alerts")