from zoneinfo import ZoneInfo
from datetime import timezone
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from . import models

def regla_blacklist(db: Session, log: models.Log):
    en_lista = db.query(models.Blacklist).filter(models.Blacklist.ip == log.source_ip).first()
    if en_lista:
        return crear_alerta(db, "ip_blacklist", "media", log.source_ip,
                            "Actividad desde una IP en lista negra")
    return None

def crear_alerta(db: Session, rule, severity, ip, desc):
    desde = datetime.utcnow() - timedelta(minutes=5)
    existe = db.query(models.Alert).filter(
        models.Alert.rule == rule,
        models.Alert.source_ip == ip,
        models.Alert.timestamp >= desde,
    ).first()
    if existe:
        return existe

    alerta = models.Alert(rule=rule, severity=severity, source_ip=ip, description=desc)
    db.add(alerta)
    db.commit()
    return alerta

def regla_fuerza_bruta(db: Session, log: models.Log):
    if log.event_type != "login_failed":
        return None
    desde = datetime.utcnow() - timedelta(minutes=5)
    intentos = db.query(models.Log).filter(
        models.Log.source_ip == log.source_ip,
        models.Log.event_type == "login_failed",
        models.Log.timestamp >= desde,
    ).count()
    if intentos >= 5:
        return crear_alerta(db, "fuerza_bruta", "alta", log.source_ip,
                            f"{intentos} logins fallidos en 5 minutos")
    return None

def regla_blacklist(db: Session, log: models.Log):
    if log.source_ip in BLACKLIST:
        return crear_alerta(db, "ip_blacklist", "media", log.source_ip,
                            "Actividad desde una IP en lista negra")
    return None

def regla_spraying(db: Session, log: models.Log):
    if log.event_type != "login_failed":
        return None
    desde = datetime.utcnow() - timedelta(minutes=5)
    usuarios = db.query(models.Log.username).filter(
        models.Log.source_ip == log.source_ip,
        models.Log.event_type == "login_failed",
        models.Log.timestamp >= desde,
    ).distinct().count()
    if usuarios >= 4:
        return crear_alerta(db, "password_spraying", "alta", log.source_ip,
                            f"{usuarios} usuarios distintos probados en 5 minutos")
    return None

def regla_horario(db: Session, log: models.Log):
    if log.event_type != "login_ok":
        return None
    hora_local = log.timestamp.replace(tzinfo=timezone.utc).astimezone(
        ZoneInfo("America/Santiago")).hour
    if hora_local < 6:
        return crear_alerta(db, "login_fuera_horario", "baja", log.source_ip,
                            f"Login exitoso de {log.username} a las {hora_local}h")
    return None

def regla_login_tras_fallos(db: Session, log: models.Log):
    if log.event_type != "login_ok":
        return None
    desde = datetime.utcnow() - timedelta(minutes=5)
    fallidos = db.query(models.Log).filter(
        models.Log.source_ip == log.source_ip,
        models.Log.event_type == "login_failed",
        models.Log.timestamp >= desde,
    ).count()
    if fallidos >= 3:
        return crear_alerta(db, "login_tras_fallos", "alta", log.source_ip,
                            f"Login exitoso de {log.username} despues de {fallidos} intentos fallidos")
    return None

REGLAS = [regla_fuerza_bruta, regla_blacklist, regla_spraying, regla_horario, regla_login_tras_fallos]

def analizar(db: Session, log: models.Log):
    for regla in REGLAS:
        regla(db, log)