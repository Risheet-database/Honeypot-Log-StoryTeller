import json
import requests
import nltk
from nltk.tokenize import word_tokenize

from shared.rabbitmq_utils import get_rabbitmq_connection, publish_message
from shared.minio_utils import minio_client

# ── GeoIP Cache (in-memory, per-worker lifetime) ──
_geo_cache = {}

def geoip_lookup(ip: str) -> dict:
    """Real GeoIP enrichment via ip-api.com with caching. Free tier: 45 req/min."""
    if not ip or ip in ("Unknown", "127.0.0.1", "0.0.0.0"):
        return {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "isp": "Unknown"}

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,as,isp",
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                }
                _geo_cache[ip] = result
                print(f"[GeoIP] {ip} → {result['country']}, {result['city']}, ASN: {result['asn']}")
                return result
    except Exception as e:
        print(f"[GeoIP] Lookup failed for {ip}: {e}")

    fallback = {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "isp": "Unknown"}
    _geo_cache[ip] = fallback
    return fallback

def process_event(event: dict):
    # Tokenize command if present
    if "input" in event and event["input"]:
        try:
            tokens = word_tokenize(event["input"])
            event["tokens"] = tokens
        except Exception:
            event["tokens"] = []
            
    # GeoIP lookup (real)
    if "src_ip" in event and event.get("country") in (None, "Unknown", ""):
        geo = geoip_lookup(event["src_ip"])
        event.update(geo)
        
    return event

def callback(ch, method, properties, body):
    msg = json.loads(body)
    file_id = msg.get("file_id")
    object_name = msg.get("object_name")
    
    print(f"[Preprocessor][START] file_id={file_id} | Stage: Raw Event Parsing + GeoIP Enrichment")
    
    # Download raw logs
    try:
        raw_events = minio_client.get_json("d1-raw-logs", object_name)
    except Exception as e:
        print(f"[Preprocessor][ERROR] file_id={file_id} | Failed to read from MinIO: {e}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return
        
    enriched_events = []
    for evt in raw_events:
        # F2: Remove noise events
        if evt.get("eventid") == "cowrie.client.kex":
            continue
            
        enriched = process_event(evt)
        enriched_events.append(enriched)
        
    # Save enriched to minio (so session_builder can use it)
    enriched_object_name = f"enriched_{object_name}"
    try:
        minio_client.put_json("d1-raw-logs", enriched_object_name, enriched_events)
    except Exception as e:
        print(f"[Preprocessor][ERROR] file_id={file_id} | Failed to write enriched events to MinIO: {e}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return
    
    # Push to session builder
    publish_message("session_builder_queue", {"file_id": file_id, "object_name": enriched_object_name})
    
    ch.basic_ack(delivery_tag=method.delivery_tag)
    print(f"[Preprocessor][END] file_id={file_id} | Enriched {len(enriched_events)} events")

def run():
    conn = get_rabbitmq_connection()
    channel = conn.channel()
    channel.queue_declare(queue='raw_events', durable=True)
    channel.queue_declare(queue='session_builder_queue', durable=True)
    
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='raw_events', on_message_callback=callback)
    
    print(" [*] Preprocessor waiting for messages.")
    channel.start_consuming()
