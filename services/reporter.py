import json
import os
import uuid
import matplotlib.pyplot as plt
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image as RLImage, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from stix2 import AttackPattern, Indicator, Relationship, Bundle

from shared.rabbitmq_utils import get_rabbitmq_connection
from shared.minio_utils import minio_client
from shared.database import SessionLocal
from shared.models import Session, NarrativeProfile, TechniqueMapping

def generate_heatmap(techniques):
    # F9: ATT&CK Heatmap using Matplotlib
    # Simple bar chart acting as a single-dimensional heatmap for techniques by confidence
    if not techniques:
        return None
        
    names = [t.name[:20] + "..." if len(t.name) > 20 else t.name for t in techniques]
    confidences = [t.confidence for t in techniques]
    
    fig, ax = plt.subplots(figsize=(6, 4))
    
    # Colormap based on confidence
    colors_list = plt.cm.Reds(confidences)
    
    ax.barh(names, confidences, color=colors_list)
    ax.set_xlabel('Confidence Level')
    ax.set_title('MITRE ATT&CK Techniques')
    ax.set_xlim(0, 1.0)
    
    plt.tight_layout()
    
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)
    return buf

def generate_pdf(session_data, profile, techniques):
    # F7: PDF Report Generation
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    story = []
    
    # Title
    story.append(Paragraph(f"Threat Intelligence Report", title_style))
    story.append(Spacer(1, 12))
    
    # Exec Summary / Profile Card
    story.append(Paragraph("Executive Summary & Attacker Profile", heading_style))
    profile_data = [
        ["Session ID", Paragraph(str(session_data.session_id), normal_style)],
        ["Source IP", Paragraph(str(session_data.src_ip), normal_style)],
        ["GeoLocation", Paragraph(f"{session_data.city}, {session_data.country}", normal_style)],
        ["Duration", Paragraph(f"{session_data.duration} seconds", normal_style)],
        ["Skill Level", Paragraph(str(profile.skill_level), normal_style)],
        ["Intent", Paragraph(str(profile.intent), normal_style)],
        ["Attack Type", Paragraph(str(profile.attack_type), normal_style)],
        ["Complexity Score", Paragraph(f"{profile.complexity_score}/10", normal_style)]
    ]
    t = Table(profile_data, colWidths=[150, 300])
    t.setStyle([('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)])
    story.append(t)
    story.append(Spacer(1, 12))
    
    # Narrative
    story.append(Paragraph("Attack Narrative", heading_style))
    story.append(Paragraph(profile.narrative, normal_style))
    story.append(Spacer(1, 12))
    
    # Command List
    story.append(Paragraph("Commands Executed Sequence", heading_style))
    if session_data.commands:
        for i, cmd in enumerate(session_data.commands, 1):
            story.append(Paragraph(f"<b>{i}.</b>  {cmd}", normal_style))
    else:
        story.append(Paragraph("No commands recorded for this session.", normal_style))
    story.append(Spacer(1, 12))
    
    # Heatmap
    heatmap_buf = generate_heatmap(techniques)
    if heatmap_buf:
        heatmap_elements = [
            Paragraph("ATT&CK Heatmap", heading_style),
            RLImage(heatmap_buf, width=400, height=250),
            Spacer(1, 12)
        ]
        story.append(KeepTogether(heatmap_elements))
        
    # Mitigation / Techniques Table
    story.append(Paragraph("MITRE Techniques", heading_style))
    if techniques:
        tech_data = [["ID", "Name", "Tactic", "Confidence"]]
        for tq in techniques:
            tech_data.append([
                tq.technique_id, 
                Paragraph(tq.name, normal_style), 
                Paragraph(tq.tactic, normal_style), 
                str(tq.confidence)
            ])
        tt = Table(tech_data, colWidths=[60, 150, 150, 80])
        tt.setStyle([('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                     ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                     ('GRID', (0, 0), (-1, -1), 1, colors.black)])
        story.append(tt)
    else:
        story.append(Paragraph("No techniques identified.", normal_style))
        
    doc.build(story)
    return pdf_buffer.getvalue()

def generate_stix(session_data, profile, techniques):
    # F8: STIX Export
    objects = []
    
    # Indicator for IP
    indicator = Indicator(
        name="Malicious IP",
        pattern=f"[ipv4-addr:value = '{session_data.src_ip}']",
        pattern_type="stix",
        valid_from=session_data.start_time
    )
    objects.append(indicator)
    
    # Attack Patterns
    for t in techniques:
        ap = AttackPattern(
            name=t.name,
            description=f"Tactic: {t.tactic}, Confidence: {t.confidence}",
            external_references=[{"source_name": "mitre-attack", "external_id": t.technique_id}]
        )
        objects.append(ap)
        # Relationship
        objects.append(Relationship(indicator, 'indicates', ap))
        
    if not objects:
        return '{"type": "bundle", "id": "bundle--empty", "objects": []}'
        
    bundle = Bundle(objects=objects)
    return bundle.serialize()

def get_report_json(session_data, profile, techniques):
    return {
        "session": {
            "session_id": session_data.session_id,
            "src_ip": session_data.src_ip,
            "country": session_data.country,
            "duration": session_data.duration,
            "commands": session_data.commands
        },
        "profile": {
            "narrative": profile.narrative,
            "skill_level": profile.skill_level,
            "intent": profile.intent,
            "attack_type": profile.attack_type,
            "score": profile.complexity_score
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

def callback(ch, method, properties, body):
    msg = json.loads(body)
    session_id = msg.get("session_id")
    
    print(f"[Reporter][START] session_id={session_id} | Stage: Report Document Generation")
    
    db = SessionLocal()
    session_data = db.query(Session).filter(Session.session_id == session_id).first()
    profile = db.query(NarrativeProfile).filter(NarrativeProfile.session_id == session_id).first()
    techniques = db.query(TechniqueMapping).filter(TechniqueMapping.session_id == session_id).all()
    
    if not session_data or not profile:
        print(f"[Reporter][ERROR] session_id={session_id} | Missing data for session!")
        db.close()
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return
        
    try:
        # 1. JSON
        json_data = get_report_json(session_data, profile, techniques)
        minio_client.put_json("d5-reports", f"{session_id}.json", json_data)
        
        # 2. STIX
        stix_json = generate_stix(session_data, profile, techniques)
        stix_data = json.loads(stix_json)
        minio_client.put_json("d5-reports", f"{session_id}_stix.json", stix_data)
        
        # 3. PDF
        pdf_bytes = generate_pdf(session_data, profile, techniques)
        pdf_stream = BytesIO(pdf_bytes)
        minio_client.client.put_object(
            "d5-reports",
            f"{session_id}.pdf",
            pdf_stream,
            length=len(pdf_bytes),
            content_type="application/pdf"
        )
        
    except Exception as e:
        print(f"[Reporter][ERROR] session_id={session_id} | Error generating reports: {e}")
        
    db.close()
    ch.basic_ack(delivery_tag=method.delivery_tag)
    print(f"[Reporter][END] session_id={session_id} | Status: Success")

def run():
    conn = get_rabbitmq_connection()
    channel = conn.channel()
    channel.queue_declare(queue='report_jobs', durable=True)
    
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='report_jobs', on_message_callback=callback)
    
    print(" [*] Reporter waiting for messages.")
    channel.start_consuming()
