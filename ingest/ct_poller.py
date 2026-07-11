#!/usr/bin/env python3
"""
PhishRadar - Ingestion des CT logs -> Snowflake, SANS serveur local.

Le script interroge directement l'API publique des Certificate Transparency
logs (RFC 6962 : get-sth / get-entries) - aucun serveur à héberger, aucun
websocket : juste du HTTP sortant vers les logs de Google, Let's Encrypt, etc.

Pipeline :
  CT logs publics (HTTP polling, ~20 s)
    -> parsing des certificats (X.509)
    -> pré-filtre marques (mots-clés + fuzzy) : ~99,9 % écarté AVANT Snowflake
    -> buffer JSONL gzip -> PUT @PHISHRADAR.RAW.CERT_STAGE
    -> COPY INTO par TASK Snowflake (sql/10_raw.sql)

Les messages produits sont au format certstream ("certificate_update"),
donc le SQL aval est inchangé.

Usage :
  export SNOWFLAKE_ACCOUNT=xxx SNOWFLAKE_USER=xxx SNOWFLAKE_PASSWORD=xxx
  python ingest/ct_poller.py
"""
import base64
import gzip
import json
import os
import sys
import time
import uuid
from pathlib import Path

import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from rapidfuzz.distance import Levenshtein

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "20"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "200"))        # certs par fichier PUT
FLUSH_SECONDS = int(os.environ.get("FLUSH_SECONDS", "60"))
MAX_ENTRIES_PER_CYCLE = int(os.environ.get("MAX_ENTRIES_PER_CYCLE", "3072"))  # par log
MAX_LOGS = int(os.environ.get("MAX_LOGS", "4"))              # nb de logs suivis
STAGE = "@PHISHRADAR.RAW.CERT_STAGE"
STATE_FILE = Path(__file__).parent / ".ct_state.json"
CONFIG_PATH = Path(__file__).parent.parent / "config" / "brands.yml"

# --- Référentiel marques (identique à la version websocket) ------------------
cfg = yaml.safe_load(CONFIG_PATH.read_text())
KEYWORDS = sorted({kw for b in cfg["brands"] for kw in b["keywords"]})
BRAND_TOKENS = sorted({kw.replace("-", "").replace("_", "") for kw in KEYWORDS})
MAX_DIST = cfg["thresholds"]["editdistance_max"]
LEET = str.maketrans("0134578", "oleastb")


def normalize(label: str) -> str:
    return label.lower().translate(LEET).replace("rn", "m").replace("-", "").replace("_", "")


def is_candidate(domain: str) -> bool:
    d = domain.lower().lstrip("*.")
    dn = normalize(d)
    if any(kw in d or kw in dn for kw in BRAND_TOKENS):
        return True
    sld = d.rsplit(".", 2)[-2] if d.count(".") >= 1 else d
    sldn = normalize(sld)
    return any(
        abs(len(sldn) - len(t)) <= MAX_DIST and Levenshtein.distance(sldn, t) <= MAX_DIST
        for t in BRAND_TOKENS if len(t) >= 6
    )


# --- Découverte des CT logs actifs (liste officielle Google) ------------------
def discover_logs() -> list[dict]:
    """Retourne les logs RFC 6962 'usable' de la liste Chrome, les plus récents d'abord."""
    data = requests.get(LOG_LIST_URL, timeout=30).json()
    logs = []
    for op in data.get("operators", []):
        for lg in op.get("logs", []):                     # RFC 6962 uniquement
            if "usable" in lg.get("state", {}):
                logs.append({"name": lg["description"], "url": lg["url"].rstrip("/") + "/"})
    logs.sort(key=lambda l: l["name"], reverse=True)      # heuristique : récents d'abord
    return logs[:MAX_LOGS]


# --- Parsing RFC 6962 ----------------------------------------------------------
def parse_entry(leaf_b64: str, extra_b64: str):
    """MerkleTreeLeaf -> (cert x509, timestamp_ms) ; gère X509 et Precert."""
    leaf = base64.b64decode(leaf_b64)
    ts_ms = int.from_bytes(leaf[2:10], "big")
    entry_type = int.from_bytes(leaf[10:12], "big")
    if entry_type == 0:                                    # X509LogEntry
        length = int.from_bytes(leaf[12:15], "big")
        der = leaf[15:15 + length]
    else:                                                  # PrecertLogEntry
        extra = base64.b64decode(extra_b64)                # PrecertChainEntry
        length = int.from_bytes(extra[0:3], "big")
        der = extra[3:3 + length]
    return x509.load_der_x509_certificate(der), ts_ms


def cert_to_message(cert, ts_ms: int, log_name: str) -> dict | None:
    """Construit un message au format certstream (SQL aval inchangé)."""
    domains = set()
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        domains.update(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        domains.add(cn[0].value)
    domains = sorted(d for d in domains if "." in d)
    if not domains:
        return None
    issuer_o = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": domains,
                "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "issuer": {"O": issuer_o[0].value if issuer_o else cert.issuer.rfc4514_string()},
                "not_before": int(cert.not_valid_before_utc.timestamp()),
                "not_after": int(cert.not_valid_after_utc.timestamp()),
            },
            "seen": ts_ms / 1000.0,
            "source": {"name": log_name},
        },
    }


# --- Snowflake -----------------------------------------------------------------
def sf_connect():
    import snowflake.connector
    return snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        password=os.environ["SNOWFLAKE_PASSWORD"],
        role=os.environ.get("SNOWFLAKE_ROLE", "PR_ENGINEER"),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE", "WH_INGEST"),
        database="PHISHRADAR", schema="RAW",
    )


def flush(buffer: list[str], conn) -> None:
    if not buffer:
        return
    fname = f"/tmp/certs_{int(time.time())}_{uuid.uuid4().hex[:8]}.jsonl.gz"
    with gzip.open(fname, "wt") as f:
        f.write("\n".join(buffer))
    conn.cursor().execute(f"PUT file://{fname} {STAGE} AUTO_COMPRESS=FALSE")
    os.remove(fname)
    print(f"[+] {len(buffer)} certs -> {STAGE}", flush=True)


# --- Boucle principale -----------------------------------------------------------
def main() -> None:
    conn = sf_connect()
    logs = discover_logs()
    print("[i] Logs suivis :", ", ".join(l["name"] for l in logs), flush=True)

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    buffer: list[str] = []
    last_flush = time.time()
    stats = {"seen": 0, "kept": 0}
    session = requests.Session()

    while True:
        for lg in logs:
            try:
                sth = session.get(lg["url"] + "ct/v1/get-sth", timeout=30).json()
                tree_size = sth["tree_size"]
                start = state.get(lg["url"], max(0, tree_size - 256))  # 1er run : pas d'historique
                end_target = min(tree_size, start + MAX_ENTRIES_PER_CYCLE)
                while start < end_target:
                    r = session.get(
                        lg["url"] + "ct/v1/get-entries",
                        params={"start": start, "end": end_target - 1}, timeout=30)
                    entries = r.json().get("entries", [])
                    if not entries:
                        break
                    for e in entries:
                        stats["seen"] += 1
                        try:
                            cert, ts_ms = parse_entry(e["leaf_input"], e["extra_data"])
                            msg = cert_to_message(cert, ts_ms, lg["name"])
                        except Exception:
                            continue                       # entrée non parsable : on passe
                        if msg and any(is_candidate(d) for d in msg["data"]["leaf_cert"]["all_domains"]):
                            stats["kept"] += 1
                            buffer.append(json.dumps(msg, separators=(",", ":")))
                    start += len(entries)                  # le log peut répondre par tranches
                state[lg["url"]] = start
            except Exception as exc:
                print(f"[!] {lg['name']} : {exc}", file=sys.stderr, flush=True)

        STATE_FILE.write_text(json.dumps(state))
        if len(buffer) >= BATCH_SIZE or (buffer and time.time() - last_flush > FLUSH_SECONDS):
            flush(buffer, conn)
            buffer.clear()
            last_flush = time.time()
        if stats["seen"] and stats["seen"] % 50_000 < MAX_ENTRIES_PER_CYCLE * MAX_LOGS:
            print(f"[i] vus={stats['seen']:,} gardés={stats['kept']:,}", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
