import json
from datetime import datetime
from sqlalchemy.orm import Session as DBSession

from shared.rabbitmq_utils import get_rabbitmq_connection, publish_message
from shared.minio_utils import minio_client
from shared.database import SessionLocal
from shared.models import Session

def callback(ch, method, properties, body):
    msg = json.loads(body)
    object_name = msg.get("object_name")
    file_id = msg.get("file_id", "Unknown")
    
    print(f"[SessionBuilder][START] file_id={file_id} | Stage: Session Extraction")
    
    try:
        enriched_events = minio_client.get_json("d1-raw-logs", object_name)
    except Exception as e:
        print(f"[SessionBuilder][ERROR] file_id={file_id} | Failed to read {object_name}: {e}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return
        
    # F3: Group by session UUID
    sessions_map = {}
    
    for evt in enriched_events:
        sid = evt.get("session")
        if not sid:
            continue
            
        if sid not in sessions_map:
            sessions_map[sid] = {
                "session_id": sid,
                "src_ip": "Unknown",
                "country": "Unknown",
                "city": "Unknown",
                "asn": "Unknown",
                "isp": "Unknown",
                "commands": [],
                "credentials": [],
                "files": [],
                "events": []
            }
            
        # Update metadata if present in this event (first connect event usually has it)
        for key in ["src_ip", "country", "city", "asn", "isp"]:
            val = evt.get(key)
            if val and val != "Unknown" and sessions_map[sid][key] == "Unknown":
                sessions_map[sid][key] = val
            
        # Extract commands strictly from cowrie.command.input events
        if evt.get("eventid") == "cowrie.command.input" and evt.get("input"):
            sessions_map[sid]["commands"].append(evt.get("input"))
            print(f"[SessionBuilder][CMD] session={sid} | Captured: {evt.get('input')}")
            
        if evt.get("username") and evt.get("password"):
            sessions_map[sid]["credentials"].append({
                "user": evt.get("username"),
                "pass": evt.get("password")
            })
            
        if evt.get("shasum"):
            sessions_map[sid]["files"].append({
                "hash": evt.get("shasum"),
                "url": evt.get("url", "")
            })
            
        if evt.get("timestamp"):
            try:
                # Handle standard ISO8601 with Z
                ts_str = evt.get("timestamp").replace("Z", "+00:00")
                ts = datetime.fromisoformat(ts_str)
                sessions_map[sid]["events"].append(ts)
            except ValueError:
                pass

    db = SessionLocal()
    
    print(f"[SessionBuilder] file_id={file_id} | Total sessions found: {len(sessions_map)}")
    
    for sid, sdata in sessions_map.items():
        print(f"[SessionBuilder] session={sid} | cmds={len(sdata['commands'])}, creds={len(sdata['credentials'])}, files={len(sdata['files'])}, events={len(sdata['events'])}")
        if not sdata["events"]:
            continue
            
        sdata["events"].sort()
        start_time = sdata["events"][0]
        end_time = sdata["events"][-1]
        duration = (end_time - start_time).total_seconds()
        
        # Retain sessions that have distinct interaction events (commands, credentials, files, or generalized activity)
        # Avoid dropping reconnaissance or automated bot brute-forcing that don't execute CLI commands
        if len(sdata["commands"]) == 0 and len(sdata["credentials"]) == 0 and len(sdata["files"]) == 0 and len(sdata["events"]) < 2:
            print(f"[SessionBuilder] session={sid} | DROPPED by noise filter (no commands, no creds, no files, <2 events)")
            continue
            
        # Store to D2
        try:
            existing = db.query(Session).filter(Session.session_id == sid).first()
            if not existing:
                new_session = Session(
                    session_id=sid,
                    src_ip=sdata["src_ip"],
                    country=sdata["country"],
                    city=sdata["city"],
                    asn=sdata["asn"],
                    isp=sdata["isp"],
                    commands=sdata["commands"],
                    credentials=sdata["credentials"],
                    files=sdata["files"],
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                db.add(new_session)
                db.commit()
                
                # Push to sessions_ready
                publish_message("sessions_ready", {"session_id": sid})
                print(f"[SessionBuilder] session={sid} | Published to sessions_ready queue")
        except Exception as db_err:
            print(f"[SessionBuilder][ERROR] session_id={sid} | DB insertion failed: {db_err}")
            db.rollback()
            
    db.close()
    ch.basic_ack(delivery_tag=method.delivery_tag)
    print(f"[SessionBuilder][END] file_id={file_id} | Status: Success")

def run():
    conn = get_rabbitmq_connection()
    channel = conn.channel()
    channel.queue_declare(queue='session_builder_queue', durable=True)
    channel.queue_declare(queue='sessions_ready', durable=True)
    
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='session_builder_queue', on_message_callback=callback)
    
    print(" [*] Session Builder waiting for messages.")
    channel.start_consuming()
