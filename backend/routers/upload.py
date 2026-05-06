import uuid
import json
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks  # type: ignore
from pydantic import ValidationError  # type: ignore

from shared.minio_utils import minio_client  # type: ignore
from shared.rabbitmq_utils import publish_message  # type: ignore
from shared.models import RawEvent  # type: ignore

router = APIRouter(prefix="/upload", tags=["upload"])

def _normalize_event(raw_event):
    """Normalize alternate Cowrie field names into standard format."""
    if not isinstance(raw_event, dict):
        return raw_event
    
    normalized = dict(raw_event)
    
    # Handle src_ip_identifier → src_ip (anonymized datasets)
    if "src_ip" not in normalized and "src_ip_identifier" in normalized:
        normalized["src_ip"] = normalized["src_ip_identifier"]
    
    # Handle session_id → session (real-world format uses session_id)
    if "session" not in normalized and "session_id" in normalized:
        normalized["session"] = normalized["session_id"]
    
    # Extract geolocation data into flat fields for downstream compatibility
    geo = normalized.get("geolocation_data", {})
    if isinstance(geo, dict):
        if "country_name" in geo and "country" not in normalized:
            normalized["country"] = geo.get("country_name")
        if "city_name" in geo and "city" not in normalized:
            normalized["city"] = geo.get("city_name")
        if "ip" in geo and "src_ip" not in normalized:
            normalized["src_ip"] = geo.get("ip")
    
    # Handle 'command' vs 'input' field names
    if "input" not in normalized and "command" in normalized:
        normalized["input"] = normalized["command"]
    
    return normalized

def _extract_events_from_data(raw_data):
    """Extract a flat list of event dicts from any Cowrie format or Simplified Demo format."""
    events = []
    
    def process_item(item):
        if not isinstance(item, dict): return
        
        # 1. Structural Cowrie Event
        if "eventid" in item:
            events.append(item)
            return
            
        # 2. Simplified Demo Input Format -> Convert to Cowrie
        if "commands" in item and isinstance(item["commands"], list):
            sid = str(uuid.uuid4())
            events.append({
                "eventid": "cowrie.session.connect",
                "session": sid,
                "src_ip": item.get("src_ip", "Unknown")
            })
            for cmd in item["commands"]:
                events.append({
                    "eventid": "cowrie.command.input",
                    "session": sid,
                    "input": cmd
                })
            for cred in item.get("credentials", []):
                events.append({
                    "eventid": "cowrie.login.success",
                    "session": sid,
                    "username": cred.get("username", cred.get("user", "")),
                    "password": cred.get("password", cred.get("pass", ""))
                })
            return
            
        # 3. Nested format logic (recursive extraction)
        keys = list(item.keys())
        if len(keys) == 1 and isinstance(item[keys[0]], list):
            # Format: {"session_id": [events]}
            for child in item[keys[0]]:
                process_item(child)
        else:
            # Blind extraction of dict values
            for val in item.values():
                if isinstance(val, list):
                    for child in val:
                        process_item(child)
                elif isinstance(val, dict):
                    process_item(val)

    if isinstance(raw_data, list):
        for item in raw_data:
            process_item(item)
    elif isinstance(raw_data, dict):
        process_item(raw_data)
        
    return events

@router.post("/")
async def upload_log_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith(('.json', '.log')):
        raise HTTPException(status_code=400, detail="Only .json or .log files are supported.")
        
    content = await file.read()
    if len(content) > 1024 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 1GB memory ingestion limit.")
        
    try:
        # 1. Try strict JSON parse first
        raw_data = json.loads(content.decode("utf-8"))  # type: ignore
        data = _extract_events_from_data(raw_data)
            
    except json.JSONDecodeError:
        # 2. Fallback to NDJSON (Newline-Delimited JSON)
        data = []
        lines = content.decode("utf-8").strip().split('\n')  # type: ignore
        for line in lines:
            if not line.strip(): continue
            try:
                parsed = json.loads(line)
                data.extend(_extract_events_from_data(parsed) if isinstance(parsed, (list, dict)) else [])
            except json.JSONDecodeError:
                pass
                
        if not data:
            raise HTTPException(status_code=400, detail="Invalid JSON or NDJSON file.")
    
    valid_events = []
    for idx, item in enumerate(data):
        try:
            normalized = _normalize_event(item)
            event = RawEvent(**normalized)
            valid_events.append(event.dict())
        except (ValidationError, Exception) as e:
            if idx < 5:  # Only log first 5 skips to avoid log spam
                print(f"Skipping invalid event at index {idx}: {e}")
            
    if not valid_events:
        raise HTTPException(status_code=400, detail="No valid events found in the uploaded file.")

    file_id = str(uuid.uuid4())
    object_name = f"{file_id}_{file.filename}"
    
    # Save to Minio
    minio_client.put_json("d1-raw-logs", object_name, valid_events)
    
    # Queue for preprocessing
    publish_message("raw_events", {"file_id": file_id, "object_name": object_name})
    
    print(f"[Upload] file_id={file_id} | {len(valid_events)} valid events from {len(data)} total")
    
    return {
        "message": "File uploaded and queued for processing.",
        "file_id": file_id,
        "valid_events_count": len(valid_events)
    }
