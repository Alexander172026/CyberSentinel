import random
from pathlib import Path
from fastapi.responses import FileResponse
from sqlalchemy import func
from typing import List
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, schemas, detection
from .database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="CyberSentinel")

@app.post("/logs", response_model=schemas.LogOut)
def ingresar_log(data: schemas.LogCreate, db: Session = Depends(get_db)):
    log = models.Log(**data.model_dump())
    db.add(log)
    db.commit()
    db.refresh(log)
    detection.analizar(db, log)  # corre las reglas con cada log nuevo
    return log

@app.get("/logs", response_model=List[schemas.LogOut])
def listar_logs(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(models.Log).order_by(models.Log.id.desc()).limit(limit).all()

@app.get("/alerts", response_model=List[schemas.AlertOut])
def listar_alertas(db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.id.desc()).all()


@app.get("/stats")
def estadisticas(db: Session = Depends(get_db)):
    por_peligro = dict(
        db.query(models.Alert.severity, func.count(models.Alert.id))
        .group_by(models.Alert.severity).all()
    )
    top_ips = (
        db.query(models.Alert.source_ip, func.count(models.Alert.id))
        .group_by(models.Alert.source_ip)
        .order_by(func.count(models.Alert.id).desc())
        .limit(5).all()
    )
    return {
        "total_logs": db.query(models.Log).count(),
        "total_alertas": db.query(models.Alert).count(),
        "alertas_por_peligro": por_peligro,
        "top_ips": [{"ip": ip, "alertas": n} for ip, n in top_ips],
    }

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).parent / "dashboard.html")

@app.get("/blacklist")
def ver_blacklist(db: Session = Depends(get_db)):
    return [b.ip for b in db.query(models.Blacklist).all()]

@app.post("/blacklist")
def agregar_ip(data: schemas.IpIn, db: Session = Depends(get_db)):
    ip = data.ip.strip()
    if ip and not db.query(models.Blacklist).filter_by(ip=ip).first():
        db.add(models.Blacklist(ip=ip))
        db.commit()
    return {"ok": True}

@app.delete("/blacklist/{ip}")
def quitar_ip(ip: str, db: Session = Depends(get_db)):
    db.query(models.Blacklist).filter_by(ip=ip).delete()
    db.commit()
    return {"ok": True}

@app.delete("/reset")
def reset(db: Session = Depends(get_db)):
    db.query(models.Log).delete()
    db.query(models.Alert).delete()
    db.commit()
    return {"ok": True}

def meter_log(db, ip, tipo, user=None, msg=None):
    log = models.Log(source_ip=ip, event_type=tipo, username=user, message=msg)
    db.add(log)
    db.commit()
    db.refresh(log)
    detection.analizar(db, log)

@app.post("/simular/{tipo}")
def simular(tipo: str, db: Session = Depends(get_db)):
    if tipo == "normal":
        for _ in range(5):
            meter_log(db, random.choice(["192.168.1.10", "192.168.1.22", "10.0.0.5"]),
                      "login_ok", random.choice(["alexander", "cony", "mituel"]), "login exitoso")
    elif tipo == "fuerza_bruta":
        for i in range(6):
            meter_log(db, "45.33.12.9", "login_failed", "admin", f"intento {i+1} fallido")
    elif tipo == "spraying":
        for u in ["admin", "root", "cony", "mituel", "test"]:
            meter_log(db, "77.88.55.1", "login_failed", u, "intento fallido")
    elif tipo == "blacklist":
        ips = [b.ip for b in db.query(models.Blacklist).all()]
        if not ips:
            db.add(models.Blacklist(ip="6.6.6.6"))
            db.commit()
            ips = ["6.6.6.6"]
        meter_log(db, random.choice(ips), "login_ok", "admin", "acceso desde ip sospechosa")
    else:
        raise HTTPException(404, "tipo no valido")
    return {"ok": True}