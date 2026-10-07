from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from .database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    username = Column(String, nullable=True)
    message = Column(Text, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule = Column(String)
    severity = Column(String)
    source_ip = Column(String, index=True)
    description = Column(Text)

class Blacklist(Base):
    __tablename__ = "blacklist"

    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, index=True)