import uuid
from sqlalchemy import Column, String, Integer, Float, JSON, ForeignKey, DateTime, Boolean
from shared.database import Base
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any
from datetime import datetime

# ================= Database Models =================

class Session(Base):
    __tablename__ = "sessions"
    
    session_id = Column(String, primary_key=True, index=True)
    src_ip = Column(String, index=True)
    country = Column(String)
    city = Column(String)
    asn = Column(String)
    isp = Column(String)
    commands = Column(JSON)      # List of command dicts
    credentials = Column(JSON)   # List of captured credentials
    files = Column(JSON)         # List of files/hashes
    duration = Column(Float)
    start_time = Column(DateTime)
    end_time = Column(DateTime)

class NarrativeProfile(Base):
    __tablename__ = "narratives"
    
    session_id = Column(String, ForeignKey("sessions.session_id"), primary_key=True)
    narrative = Column(String)
    skill_level = Column(String)
    intent = Column(String)
    attack_type = Column(String)
    complexity_score = Column(Float)
    # F5: Attacker Profiling
    error_rate = Column(Float, default=0.0)
    tools_identified = Column(JSON, default=[])
    tool_count = Column(Integer, default=0)
    obfuscation_detected = Column(Boolean, default=False)

class TechniqueMapping(Base):
    __tablename__ = "techniques"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("sessions.session_id"), index=True)
    technique_id = Column(String, index=True)
    name = Column(String)
    tactic = Column(String)
    confidence = Column(Float)

# ================= Pydantic Models =================

class RawEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    eventid: str
    session: Optional[str] = None
    src_ip: Optional[str] = None
    timestamp: Optional[str] = None
    message: Optional[str] = None
    input: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    shasum: Optional[str] = None
    dest_port: Optional[int] = None

class SessionData(BaseModel):
    session_id: str
    src_ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    commands: List[dict] = []
    credentials: List[dict] = []
    files: List[dict] = []
    duration: float = 0.0
    start_time: str
    end_time: str
