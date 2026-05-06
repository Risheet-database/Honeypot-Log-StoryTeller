import sys
import os

# Ensure we can import from shared and services
sys.path.append('c:\\Users\\rishe\\OneDrive\\Desktop\\Honeypot')

from shared.database import SessionLocal
from shared.models import Session, NarrativeProfile, TechniqueMapping
from services.reporter import generate_pdf
from shared.minio_utils import minio_client
from io import BytesIO

def patch_pdf(session_id):
    db = SessionLocal()
    session_data = db.query(Session).filter(Session.session_id == session_id).first()
    profile = db.query(NarrativeProfile).filter(NarrativeProfile.session_id == session_id).first()
    techniques = db.query(TechniqueMapping).filter(TechniqueMapping.session_id == session_id).all()

    if not session_data or not profile:
        print(f"Session {session_id} not found.")
        return

    pdf_bytes = generate_pdf(session_data, profile, techniques)
    pdf_stream = BytesIO(pdf_bytes)
    
    minio_client.client.put_object(
        "d5-reports",
        f"{session_id}.pdf",
        pdf_stream,
        length=len(pdf_bytes),
        content_type="application/pdf"
    )
    print(f"Updated {session_id}.pdf in Minio")

if __name__ == '__main__':
    patch_pdf("c9281a8c-test")
