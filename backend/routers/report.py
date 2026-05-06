from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from shared.database import get_db
from shared.models import Session, NarrativeProfile, TechniqueMapping

router = APIRouter(prefix="/report", tags=["report"])

@router.get("/{session_id}")
def get_report(session_id: str, db: DBSession = Depends(get_db)):
    session_data = db.query(Session).filter(Session.session_id == session_id).first()
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")
        
    narrative = db.query(NarrativeProfile).filter(NarrativeProfile.session_id == session_id).first()
    techniques = db.query(TechniqueMapping).filter(TechniqueMapping.session_id == session_id).all()
    
    return {
        "session": {
            "session_id": session_data.session_id,
            "src_ip": session_data.src_ip,
            "country": session_data.country,
            "city": session_data.city,
            "asn": session_data.asn,
            "isp": session_data.isp,
            "duration": session_data.duration,
            "start_time": session_data.start_time,
            "end_time": session_data.end_time,
            "commands": session_data.commands if session_data.commands else [],
            "commands_count": len(session_data.commands) if session_data.commands else 0,
            "credentials": session_data.credentials,
        },
        "profile": {
            "narrative": narrative.narrative if narrative else None,
            "skill_level": narrative.skill_level if narrative else "Unknown",
            "intent": narrative.intent if narrative else "Unknown",
            "attack_type": narrative.attack_type if narrative else "Unknown",
            "score": narrative.complexity_score if narrative else 0.0,
            "error_rate": narrative.error_rate if narrative else 0.0,
            "tools_identified": narrative.tools_identified if narrative else [],
            "tool_count": narrative.tool_count if narrative else 0,
            "obfuscation_detected": narrative.obfuscation_detected if narrative else False,
        },
        "techniques": [
            {
                "id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "confidence": t.confidence
            } for t in techniques
        ]
    }
