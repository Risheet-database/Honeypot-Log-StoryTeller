from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from shared.database import get_db
from shared.models import Session, NarrativeProfile

router = APIRouter(prefix="/status", tags=["status"])

@router.get("/{file_id}")
def get_status(file_id: str, db: DBSession = Depends(get_db)):
    # Since we process asynchronously, the status is determined by whether 
    # the sessions derived from this file (or any sessions if we don't strictly track file_id -> session_id)
    # are present. For simplicity, we can just return total sessions processed.
    # In a full production app we would track job state in Redis or DB.
    
    session_count = db.query(Session).count()
    narrative_count = db.query(NarrativeProfile).count()
    
    return {
        "file_id": file_id,
        "status": "Processing or Completed",
        "sessions_extracted": session_count,
        "narratives_generated": narrative_count
    }

@router.get("/sessions/list")
def list_sessions(db: DBSession = Depends(get_db)):
    sessions = db.query(Session).order_by(Session.start_time.desc()).limit(50).all()
    return [{"session_id": s.session_id, "src_ip": s.src_ip, "duration": s.duration, "start": s.start_time} for s in sessions]
