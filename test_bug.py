import json
from shared.models import RawEvent
from pydantic import ValidationError

def run_test():
    with open("tests/sample_cowrie.json") as f:
        data = json.load(f)
        
    valid_events = []
    for idx, item in enumerate(data):
        try:
            event = RawEvent(**item)
            valid_events.append(event.dict())
        except ValidationError as e:
            print(f"Skipping invalid event at index {idx}: {e}")
            
    print(f"Valid events: {len(valid_events)}")
    
    # Simulate preprocessor
    enriched_events = []
    for evt in valid_events:
        if evt.get("eventid") == "cowrie.client.kex":
            continue
        if "input" in evt and evt["input"]:
            evt["tokens"] = evt["input"].split()
        enriched_events.append(evt)
        
    # Simulate session_builder
    sessions_map = {}
    for evt in enriched_events:
        sid = evt.get("session")
        if not sid:
            continue
            
        if sid not in sessions_map:
            sessions_map[sid] = {
                "session_id": sid,
                "commands": [],
            }
            
        print(f"Checking event {evt.get('eventid')} with input {evt.get('input')}")
        if evt.get("eventid") == "cowrie.command.input" and evt.get("input"):
            sessions_map[sid]["commands"].append(evt.get("input"))
            print(f"-> Added command! Count is now {len(sessions_map[sid]['commands'])}")
            
    for sid, sdata in sessions_map.items():
        print(f"Session {sid} has {len(sdata['commands'])} commands: {sdata['commands']}")
        
if __name__ == "__main__":
    run_test()
