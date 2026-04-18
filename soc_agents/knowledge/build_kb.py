"""
Build ChromaDB knowledge base with MITRE ATT&CK, SOC playbooks, and detection rules.
Run this once to initialize the knowledge base.
"""
import json
import os
from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

# MITRE ATT&CK Tactics and Techniques (curated for this lab)
MITRE_DATA = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary uses brute force techniques to attempt access to accounts",
        "detection": "Monitor EventCode 4625 (failed logons) for patterns > 5 attempts"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence, Privilege Escalation, Initial Access",
        "description": "Adversary uses legitimate user accounts to maintain access",
        "detection": "Monitor 4624, 4625, 4648 for anomalous logon patterns"
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversary scans targets to identify services and vulnerabilities",
        "detection": "Monitor web server 404 errors, port scanning patterns in network logs"
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates accounts to identify targets",
        "detection": "Monitor EventCode 4720, 4728 for AD enumeration"
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversary extracts credentials from OS",
        "detection": "Monitor process execution of lsass access, mimikatz patterns"
    }
}

SOC_PLAYBOOKS = {
    "password_spray": """
    # Password Spray Playbook
    
    Trigger: EventCode=4625 count > 5 in 5 minutes
    
    Investigation Steps:
    1. Identify source IPs: index=windows_events EventCode=4625 | stats count by src_ip
    2. Identify target accounts: | stats count by Account_Name
    3. Check for successful logons: EventCode=4624 same IPs
    4. Lookup IP reputation: internal vs external
    5. Map to T1110 (Brute Force)
    
    Containment:
    - Block source IP in firewall
    - Reset targeted accounts
    - Check for lateral movement (4648 events)
    """,
    
    "web_scanner": """
    # Web Scanner Detection Playbook
    
    Trigger: Nginx 404 errors > 15 per IP in 5 minutes
    
    Investigation Steps:
    1. Identify source IP: index=linux_web status=404 | stats count by clientip
    2. Check request patterns: | stats count by request path
    3. Verify no legitimate traffic: check if IP is internal
    4. Look for followup: check auth attempts from same IP
    5. Map to T1595 (Active Scanning)
    
    Containment:
    - Block IP in firewall
    - Review web server logs for any successful requests
    - Check for web shell uploads
    """,
    
    "linux_identity_change": """
    # Linux Identity Change Playbook
    
    Trigger: auditd key=identity_changes events
    
    Investigation Steps:
    1. Get details: index=linux_audit key=identity_changes
    2. Check what changed: /etc/passwd, /etc/shadow, /etc/sudoers
    3. Identify who made change: username, uid, process
    4. Check for persistence: new users, cron jobs
    5. Map to T1098 (Account Manipulation)
    
    Containment:
    - Review changes and revert if unauthorized
    - Check for backdoor accounts
    - Review command history (bash_history)
    """
}

def build_knowledge_base():
    """Initialize ChromaDB with MITRE ATT&CK and playbooks."""
    persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
    Path(persist_dir).parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize ChromaDB
    client = chromadb.PersistentClient(path=persist_dir)
    
    # Create collections
    mitre_collection = client.get_or_create_collection(
        name="mitre_attack",
        metadata={"hnsw:space": "cosine"}
    )
    playbook_collection = client.get_or_create_collection(
        name="soc_playbooks",
        metadata={"hnsw:space": "cosine"}
    )
    
    # Initialize embedder
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    
    # Add MITRE ATT&CK techniques
    mitre_docs = []
    mitre_ids = []
    mitre_metadata = []
    
    for tech_id, tech_data in MITRE_DATA.items():
        doc = f"{tech_id}: {tech_data['name']}. {tech_data['description']}. Detection: {tech_data['detection']}"
        mitre_docs.append(doc)
        mitre_ids.append(tech_id)
        mitre_metadata.append({
            "technique_id": tech_id,
            "name": tech_data["name"],
            "tactic": tech_data["tactic"]
        })
    
    if mitre_docs:
        embeddings = embedder.encode(mitre_docs, show_progress_bar=False)
        mitre_collection.add(
            ids=mitre_ids,
            embeddings=embeddings.tolist(),
            documents=mitre_docs,
            metadatas=mitre_metadata
        )
        print(f"Ingested {len(mitre_docs)} MITRE ATT&CK techniques")
    
    # Add playbooks
    playbook_docs = []
    playbook_ids = []
    playbook_metadata = []
    
    for playbook_name, playbook_content in SOC_PLAYBOOKS.items():
        playbook_docs.append(playbook_content)
        playbook_ids.append(playbook_name)
        playbook_metadata.append({"playbook_name": playbook_name})
    
    if playbook_docs:
        embeddings = embedder.encode(playbook_docs, show_progress_bar=False)
        playbook_collection.add(
            ids=playbook_ids,
            embeddings=embeddings.tolist(),
            documents=playbook_docs,
            metadatas=playbook_metadata
        )
        print(f"Ingested {len(playbook_docs)} SOC playbooks")
    
    print(f"Knowledge base initialized at: {persist_dir}")

if __name__ == "__main__":
    build_knowledge_base()
