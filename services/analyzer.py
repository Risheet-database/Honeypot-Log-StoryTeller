import json
import os
import re
import time
from datetime import datetime
from groq import Groq
from sqlalchemy.orm import Session as DBSession

from shared.rabbitmq_utils import get_rabbitmq_connection, publish_message
from shared.database import SessionLocal
from shared.models import Session, NarrativeProfile, TechniqueMapping
from configs.settings import settings

# ──────────────────────────────────────────────────────────────────────
#  STRICT command → intent map.  Only these mappings are allowed.
#  No inference, no guessing.  If a command doesn't match, it is
#  labeled "Unclassified Command" and carries NO MITRE tag.
# ──────────────────────────────────────────────────────────────────────

TOOL_INTENT = {
    # Reconnaissance / Discovery
    "ls":       {"intent": "Directory Listing",           "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.90},
    "pwd":      {"intent": "Current Directory Check",     "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "whoami":   {"intent": "Current User Identification", "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.90},
    "id":       {"intent": "User/Group Enumeration",      "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.90},
    "uname":    {"intent": "System Information Gathering", "mitre": "T1082", "mitre_name": "System Information Discovery",             "tactic": "Discovery",           "confidence": 0.90},
    "hostname": {"intent": "Host Identification",         "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "ifconfig": {"intent": "Network Configuration Check", "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "ip":       {"intent": "Network Configuration Check", "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "netstat":  {"intent": "Active Connections Check",    "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "ps":       {"intent": "Process Enumeration",         "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.85},
    "w":        {"intent": "Logged-in Users Check",       "mitre": "T1082", "mitre_name": "System Information Discovery",              "tactic": "Discovery",           "confidence": 0.80},
    "cat":      None,  # special-cased below for /etc/passwd vs /etc/shadow

    # Payload Download
    "wget":     {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.90},
    "curl":     {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.90},
    "fetch":    {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.85},
    "scp":      {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.85},
    "ftp":      {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.80},
    "tftp":     {"intent": "Payload Download",            "mitre": "T1105", "mitre_name": "Ingress Tool Transfer",                     "tactic": "Command and Control", "confidence": 0.80},

    # Payload Execution
    "bash":     {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.85},
    "sh":       {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.85},
    "zsh":      {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.85},
    "python":   {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.80},
    "perl":     {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.80},
    "php":      {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.80},
    "ruby":     {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.80},
    "node":     {"intent": "Payload Execution",           "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter",         "tactic": "Execution",           "confidence": 0.80},

    # Preparation
    "chmod":    {"intent": "Preparation for Execution",   "mitre": "T1222", "mitre_name": "File and Directory Permissions Modification","tactic": "Defense Evasion",      "confidence": 0.85},

    # Anti-Forensics
    "rm":       {"intent": "File Deletion",               "mitre": "T1070.004", "mitre_name": "File Deletion",                        "tactic": "Defense Evasion",      "confidence": 0.85},
    "shred":    {"intent": "Secure File Deletion",        "mitre": "T1070.004", "mitre_name": "File Deletion",                        "tactic": "Defense Evasion",      "confidence": 0.90},

    # Persistence (only if explicitly present)
    "crontab":  {"intent": "Scheduled Task Persistence",  "mitre": "T1053.003", "mitre_name": "Scheduled Task: Cron",                 "tactic": "Persistence",         "confidence": 0.90},
    "systemctl":{"intent": "Service Manipulation",        "mitre": "T1543.002", "mitre_name": "Create or Modify System Process",      "tactic": "Persistence",         "confidence": 0.85},
}


def _classify_command(cmd):
    """Strictly classify a single command.  Returns (intent_str, mitre_dict|None)."""
    parts = cmd.strip().split()
    if not parts:
        return None, None

    tool = parts[0].lower().lstrip('./')

    # ./something  →  execution
    if cmd.strip().startswith('./'):
        return "Payload Execution", {"mitre": "T1059", "mitre_name": "Command and Scripting Interpreter", "tactic": "Execution", "confidence": 0.85}

    # Special handling for 'cat'
    if tool == "cat":
        target = " ".join(parts[1:]).lower()
        if "/etc/shadow" in target or "id_rsa" in target:
            return "Credential Dumping", {"mitre": "T1003.008", "mitre_name": "OS Credential Dumping", "tactic": "Credential Access", "confidence": 0.85}
        if "/etc/passwd" in target:
            return "Credential Enumeration", {"mitre": "T1087", "mitre_name": "Account Discovery", "tactic": "Discovery", "confidence": 0.85}
        return "File Read", None  # generic cat with no security implication

    entry = TOOL_INTENT.get(tool)
    if entry is None:
        return None, None  # Unrecognised → NO intent, NO MITRE

    return entry["intent"], {"mitre": entry["mitre"], "mitre_name": entry["mitre_name"], "tactic": entry["tactic"], "confidence": entry["confidence"]}


def compute_complexity_score(commands):
    if not commands:
        return 0.0
    score = 0.0
    tools = set()
    for cmd in commands:
        parts = cmd.strip().split()
        if parts:
            tools.add(parts[0].lower().lstrip('./'))
        if any(c in cmd for c in ['|', '&&', ';', '$', '\\', '`']):
            score += 0.3
        if len(cmd) > 50:
            score += 0.2
    score += len(tools) * 0.15
    return round(min(score, 10.0), 1)


def map_mitre_and_extract_intents(commands, db_session, session_id, session_data):
    """Strict, session-isolated MITRE mapping.  Only maps what is explicitly present."""

    found_techniques = {}
    per_cmd_intents = []  # ordered list of {"raw": cmd, "intent": str}

    for cmd in (commands or []):
        intent, mitre = _classify_command(cmd)
        if intent:
            per_cmd_intents.append({"raw": cmd, "intent": intent})
            if mitre:
                tid = mitre["mitre"]
                if tid not in found_techniques:
                    found_techniques[tid] = {
                        "id": tid,
                        "name": mitre["mitre_name"],
                        "tactic": mitre["tactic"],
                        "confidence": mitre["confidence"],
                    }
                else:
                    # Repeated evidence → small boost, capped
                    found_techniques[tid]["confidence"] = round(
                        min(found_techniques[tid]["confidence"] + 0.03, 0.95), 2
                    )
        else:
            per_cmd_intents.append({"raw": cmd, "intent": "Unclassified Command"})

    # Brute force: ONLY if ≥2 failed login attempts exist in THIS session
    creds = session_data.credentials or []
    failed_logins = [c for c in creds if c.get("success") is False or c.get("eventid", "").endswith(".failed")]
    # Fallback: if no explicit success/fail flag, count multiple distinct attempts as brute-force evidence
    if not failed_logins and len(creds) >= 2:
        failed_logins = creds  # treat multiple attempts as evidence
    if len(failed_logins) >= 2:
        bf_confidence = round(min(0.60 + len(failed_logins) * 0.05, 0.95), 2)
        found_techniques["T1110"] = {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": bf_confidence}
        per_cmd_intents.append({"raw": f"{len(failed_logins)} failed login attempts", "intent": "Credential Brute Force"})

    # Persist to DB
    for tid, tech in found_techniques.items():
        db_session.add(TechniqueMapping(
            session_id=session_id,
            technique_id=tid,
            name=tech["name"],
            tactic=tech["tactic"],
            confidence=float(tech["confidence"]),
        ))
    db_session.commit()

    # Build ordered unique intent list (preserves attack sequence)
    seen = set()
    flat_intents = []
    for item in per_cmd_intents:
        i = item["intent"]
        if i != "Unclassified Command" and i not in seen:
            seen.add(i)
            flat_intents.append(i)

    return found_techniques, flat_intents, per_cmd_intents


# ──────────────────────────────────────────────
#  Skill Level & Attack Type  (strict evidence)
# ──────────────────────────────────────────────

def _derive_skill_level(flat_intents):
    """
    Script Kiddie : only recon / brute-force / basic commands
    Intermediate  : multi-step chain  (download + execute)
    Advanced      : persistence / lateral movement explicitly detected
    """
    has_download = "Payload Download" in flat_intents
    has_execute  = "Payload Execution" in flat_intents
    has_persist  = any("Persistence" in i or "Scheduled Task" in i or "Service Manipulation" in i for i in flat_intents)

    if has_persist:
        return "Advanced"
    if has_download and has_execute:
        return "Intermediate"
    return "Script Kiddie"


def _derive_attack_type(flat_intents, commands, credentials):
    if not commands and len(credentials) >= 2:
        return "Automated SSH Brute Force"
    if not commands and not credentials:
        return "Network Reconnaissance / Port Scanning"

    has_download = "Payload Download" in flat_intents
    has_execute  = "Payload Execution" in flat_intents

    if has_download and has_execute:
        return "Automated Malware Deployment"
    if has_download:
        return "Payload Staging"
    if has_execute:
        return "Command Execution"

    # Pure recon intents only
    recon_intents = {"Directory Listing", "Current Directory Check", "Current User Identification",
                     "User/Group Enumeration", "System Information Gathering", "Host Identification",
                     "Network Configuration Check", "Active Connections Check", "Process Enumeration",
                     "Logged-in Users Check", "Credential Enumeration", "File Read"}
    if flat_intents and all(i in recon_intents or i == "Credential Brute Force" for i in flat_intents):
        return "System Reconnaissance"

    return "Exploratory Activity"


# ──────────────────────────────────────────────
#  F5: Attacker Profiling Helpers
# ──────────────────────────────────────────────

def _compute_error_rate(commands):
    """Detect failed commands and return (error_rate_float, failed_count)."""
    if not commands:
        return 0.0
    failure_indicators = ["command not found", "permission denied", "no such file",
                          "not found", "access denied", "operation not permitted"]
    failed = sum(1 for c in commands if any(f in c.lower() for f in failure_indicators))
    return round(failed / len(commands), 2) if commands else 0.0

def _compute_tool_diversity(commands):
    """Return (unique_tools_list, count)."""
    tools = set()
    for cmd in (commands or []):
        parts = cmd.strip().split()
        if parts:
            tools.add(parts[0].lower().lstrip('./'))
    tools_list = sorted(tools)
    return tools_list, len(tools_list)

def _detect_obfuscation(commands):
    """Detect base64, hex, eval, encoded payloads."""
    indicators = ['base64', 'eval(', 'eval ', '\\x', '0x', 'xxd', 'printf',
                  '${', '$((', 'echo -e', 'echo -n']
    for cmd in (commands or []):
        if any(ind in cmd.lower() for ind in indicators):
            return True
    return False


# ──────────────────────────────────────────────
#  LLM Narrative  (min 100 words, 3 retries)
# ──────────────────────────────────────────────

def _call_groq_with_retry(client, messages, max_retries=3):
    """Call Groq with exponential backoff. Returns parsed JSON or None."""
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                messages=messages,
                model="llama-3.1-8b-instant",
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            result = json.loads(response.choices[0].message.content)
            # JSON schema validation
            if "narrative" in result and "skill_level" in result and "attack_type" in result:
                return result
            print(f"[Groq] Attempt {attempt+1}: missing required JSON keys, retrying...")
        except Exception as e:
            print(f"[Groq] Attempt {attempt+1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s
    return None


def _format_timestamp(ts):
    """Convert a datetime or ISO string to human-readable format like '24 March 2026, 12:00:00'."""
    if not ts:
        return "at an unknown time"
    try:
        if isinstance(ts, str):
            # Handle ISO formats: 2026-03-24T12:00:00Z or 2026-03-24T12:00:00
            ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
        elif isinstance(ts, datetime):
            dt = ts
        else:
            return "at an unknown time"
        return dt.strftime("%d %B %Y, %H:%M:%S")
    except Exception:
        return "at an unknown time"


def generate_llm_profile(session_data, complexity_score, flat_intents, per_cmd_intents, pre_skill, pre_attack):
    """Generates a narrative that ONLY describes what was observed in THIS session."""

    cmds = session_data.commands or []
    creds = session_data.credentials or []
    formatted_time = _format_timestamp(session_data.start_time)

    if not cmds and not creds:
        ip = session_data.src_ip or "Unknown"
        country = session_data.country or "Unknown"
        dur = session_data.duration or 0
        narrative = (
            f"On {formatted_time}, a connection was observed from {ip} ({country}) lasting {dur} seconds. "
            "No commands were executed and no login credentials were submitted. "
            "This is consistent with an automated port scan or a dropped connection."
        )
        return {"narrative": narrative, "skill_level": pre_skill, "intent": "None observed", "attack_type": pre_attack}

    cmd_intent_lines = "\n".join(
        f"  {i+1}. \"{item['raw']}\"  →  {item['intent']}"
        for i, item in enumerate(per_cmd_intents)
    )

    facts = {
        "ip": session_data.src_ip or "Unknown",
        "country": session_data.country or "Unknown",
        "city": session_data.city or "Unknown",
        "asn": session_data.asn or "Unknown",
        "isp": session_data.isp or "Unknown",
        "duration": session_data.duration or 0,
        "cmd_count": len(cmds),
        "cred_count": len(creds),
        "start_time": formatted_time,
    }

    if not settings.GROQ_API_KEY:
        return _build_fallback_narrative(facts, flat_intents, per_cmd_intents, pre_skill, pre_attack)

    client = Groq(api_key=settings.GROQ_API_KEY)

    prompt = f"""Write a detailed honeypot incident summary for a SOC analyst. The narrative MUST be at least 100 words.

SESSION DATA (this session ONLY):
- Timestamp: {facts['start_time']}
- Source IP: {facts['ip']} ({facts['city']}, {facts['country']}, ASN: {facts['asn']}, ISP: {facts['isp']})
- Duration: {facts['duration']}s
- Commands executed: {facts['cmd_count']}
- Login attempts: {facts['cred_count']}

OBSERVED COMMAND SEQUENCE (these are the ONLY actions that occurred):
{cmd_intent_lines}

Pre-computed classification: {pre_attack}
Pre-computed skill level: {pre_skill}

ABSOLUTE RULES:
1. Describe ONLY the actions listed above. Nothing else happened.
2. Use intent labels, NOT raw commands.
3. Do NOT use phrases: "gained interactive shell", "established foothold", "brute force" (unless Credential Brute Force intent is listed), "persistence" (unless a persistence intent is listed), "lateral movement", "data exfiltration".
4. Do NOT speculate about outcomes.
5. Write at least 100 words. Describe the full attack sequence, the geolocation context, and the classification rationale.
6. Include the source IP, geographic origin, timestamp, and observed behavioral intents in your description.
7. Use the exact timestamp provided above. NEVER output placeholder text like "<date>" or "<time>".

Return valid JSON:
{{
  "narrative": "<your detailed factual summary, minimum 100 words>",
  "skill_level": "{pre_skill}",
  "intent": "{', '.join(flat_intents) if flat_intents else 'None observed'}",
  "attack_type": "{pre_attack}"
}}"""

    messages = [
        {"role": "system", "content": "You are a factual SOC report writer. Output valid JSON. Describe only observed actions. Write at least 100 words. Never speculate."},
        {"role": "user", "content": prompt},
    ]

    result = _call_groq_with_retry(client, messages)

    if result:
        narrative = result.get("narrative", "")

        # If < 100 words, re-prompt once to expand
        word_count = len(narrative.split())
        if word_count < 100:
            print(f"[Analyzer] Narrative too short ({word_count} words), re-prompting...")
            messages.append({"role": "assistant", "content": json.dumps(result)})
            messages.append({"role": "user", "content": f"The narrative is only {word_count} words. Please expand it to at least 100 words while keeping it factual. Include geographic context, attack flow description, and classification rationale. Return the same JSON structure."})
            expanded = _call_groq_with_retry(client, messages, max_retries=2)
            if expanded and len(expanded.get("narrative", "").split()) >= word_count:
                result = expanded
                narrative = result.get("narrative", "")

        # Post-generation validation: strip banned phrases
        banned = ["interactive shell", "established foothold", "lateral movement", "data exfiltration"]
        if "Credential Brute Force" not in flat_intents:
            banned.append("brute force")
        if not any("Persistence" in i or "Scheduled Task" in i for i in flat_intents):
            banned.append("persistence")
        for phrase in banned:
            narrative = re.sub(re.escape(phrase), "command execution", narrative, flags=re.IGNORECASE)

        # Strip any remaining date/time placeholders
        narrative = re.sub(r'<date>', facts.get('start_time', 'at an unknown time'), narrative, flags=re.IGNORECASE)
        narrative = re.sub(r'<time>', facts.get('start_time', 'at an unknown time'), narrative, flags=re.IGNORECASE)

        result["narrative"] = narrative
        result["skill_level"] = pre_skill
        result["attack_type"] = pre_attack
        return result

    print("[Analyzer] All Groq retries failed, using fallback.")
    return _build_fallback_narrative(facts, flat_intents, per_cmd_intents, pre_skill, pre_attack)


def _build_fallback_narrative(facts, flat_intents, per_cmd_intents, skill, attack):
    intent_str = ", ".join(flat_intents) if flat_intents else "no classified actions"
    # Build a detailed fallback that meets the 100-word minimum
    parts = [
        f"On {facts.get('start_time', 'at an unknown time')}, an incident was recorded from source IP {facts['ip']}, geolocated to {facts['city']}, {facts['country']} (ASN: {facts['asn']}, ISP: {facts['isp']}).",
        f"The session lasted {facts['duration']} seconds during which {facts['cmd_count']} command(s) were executed and {facts['cred_count']} login attempt(s) were recorded.",
    ]
    if per_cmd_intents:
        steps = "; ".join(f"{item['intent']}" for item in per_cmd_intents if item['intent'] != 'Unclassified Command')
        if steps:
            parts.append(f"The observed attack sequence consisted of the following actions: {steps}.")
    parts.append(f"Based on the behavioral analysis, this session has been classified as {attack} with a {skill} threat level.")
    parts.append(f"The observed intents include: {intent_str}.")
    parts.append("This assessment is derived from the commands executed within the session and does not include any speculative analysis.")

    narrative = " ".join(parts)
    return {"narrative": narrative, "skill_level": skill, "intent": intent_str, "attack_type": attack}


# ──────────────────────────────────────────────
#  Worker callback  (session-isolated)
# ──────────────────────────────────────────────

def callback(ch, method, properties, body):
    msg = json.loads(body)
    session_id = msg.get("session_id")
    print(f"[Analyzer][START] session_id={session_id}")

    db = SessionLocal()
    session_data = db.query(Session).filter(Session.session_id == session_id).first()

    if not session_data:
        print(f"[Analyzer][ERROR] session_id={session_id} | not found in DB")
        db.close()
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return

    # All analysis is scoped to THIS session_data only — zero carry-over
    try:
        found_techniques, flat_intents, per_cmd_intents = map_mitre_and_extract_intents(
            session_data.commands or [], db, session_id, session_data
        )
    except Exception as e:
        print(f"[Analyzer][ERROR] session_id={session_id} | MITRE mapping failed: {e}")
        flat_intents, per_cmd_intents = [], []

    complexity = compute_complexity_score(session_data.commands)
    pre_skill  = _derive_skill_level(flat_intents)
    pre_attack = _derive_attack_type(flat_intents, session_data.commands or [], session_data.credentials or [])

    # F5: Attacker Profiling
    error_rate = _compute_error_rate(session_data.commands or [])
    tools_list, tool_count = _compute_tool_diversity(session_data.commands or [])
    obfuscation = _detect_obfuscation(session_data.commands or [])

    print(f"[Analyzer] session={session_id} | skill={pre_skill} attack={pre_attack} tools={tool_count} obfuscation={obfuscation}")

    llm_output = generate_llm_profile(session_data, complexity, flat_intents, per_cmd_intents, pre_skill, pre_attack)

    profile = NarrativeProfile(
        session_id=session_id,
        narrative=llm_output.get("narrative", ""),
        skill_level=llm_output.get("skill_level", pre_skill),
        intent=llm_output.get("intent", ""),
        attack_type=llm_output.get("attack_type", pre_attack),
        complexity_score=complexity,
        error_rate=error_rate,
        tools_identified=tools_list,
        tool_count=tool_count,
        obfuscation_detected=obfuscation,
    )
    db.add(profile)
    try:
        db.commit()
    except Exception as e:
        print(f"[Analyzer][ERROR] DB commit: {e}")
        db.rollback()

    db.close()
    publish_message("report_jobs", {"session_id": session_id})
    ch.basic_ack(delivery_tag=method.delivery_tag)
    print(f"[Analyzer][END] session_id={session_id} | OK")


def run():
    conn = get_rabbitmq_connection()
    ch = conn.channel()
    ch.queue_declare(queue='sessions_ready', durable=True)
    ch.queue_declare(queue='report_jobs', durable=True)
    ch.basic_qos(prefetch_count=1)
    ch.basic_consume(queue='sessions_ready', on_message_callback=callback)
    print(" [*] Analyzer waiting for messages.")
    ch.start_consuming()
