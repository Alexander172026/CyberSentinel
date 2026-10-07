from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class LogCreate(BaseModel):
    source_ip: str
    event_type: str
    username: Optional[str] = None
    message: Optional[str] = None

class LogOut(LogCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    rule: str
    severity: str
    source_ip: str
    description: str

class IpIn(BaseModel):
    ip: str