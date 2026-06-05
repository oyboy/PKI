import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Iterable, Optional

ZERO_HASH = "0" * 64
DEFAULT_LOG = "./pki/audit/audit.log"
DEFAULT_CHAIN = "./pki/audit/chain.dat"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_record(record):
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


def audit_paths_from_out_dir(out_dir=None, log_file=None, chain_file=None):
    if log_file:
        log = log_file
    else:
        base = out_dir or "./pki"
        if os.path.basename(os.path.normpath(base)) == "certs":
            base = os.path.dirname(os.path.normpath(base)) or "."
        log = os.path.join(base, "audit", "audit.log")
    chain = chain_file or os.path.join(os.path.dirname(log), "chain.dat")
    return log, chain


class AuditLogger:
    def __init__(self, log_file=DEFAULT_LOG, chain_file=None):
        self.log_file = log_file
        self.chain_file = chain_file or os.path.join(os.path.dirname(log_file), "chain.dat")
        os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.chain_file) or ".", exist_ok=True)
        if not os.path.exists(self.log_file):
            open(self.log_file, "a", encoding="utf-8").close()
        if not os.path.exists(self.chain_file):
            with open(self.chain_file, "w", encoding="utf-8") as f:
                f.write(self._last_hash_from_log() + "\n")

    def _last_hash_from_log(self):
        last = ZERO_HASH
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    last = json.loads(line).get("integrity", {}).get("hash", last)
        except FileNotFoundError:
            pass
        return last

    def last_hash(self):
        try:
            val = open(self.chain_file, "r", encoding="utf-8").read().strip().splitlines()[-1]
            return val if val else self._last_hash_from_log()
        except Exception:
            return self._last_hash_from_log()

    def write(self, level, operation, status, message, metadata=None):
        metadata = sanitize_metadata(metadata or {})
        rec = {
            "timestamp": utc_now(),
            "level": level,
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata,
            "integrity": {"prev_hash": self.last_hash()}
        }
        rec["integrity"]["hash"] = _hash_record(rec)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(canonical(rec) + "\n")
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(rec["integrity"]["hash"] + "\n")
        return rec


def sanitize_metadata(obj):
    banned = ("private_key", "passphrase", "password", "secret", "key_pem")
    if isinstance(obj, dict):
        return {k: ("***" if any(b in k.lower() for b in banned) else sanitize_metadata(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_metadata(x) for x in obj]
    return obj


def log_event(operation, status, message, metadata=None, level="AUDIT", out_dir=None, log_file=None):
    log, chain = audit_paths_from_out_dir(out_dir=out_dir, log_file=log_file)
    return AuditLogger(log, chain).write(level, operation, status, message, metadata)


def read_records(log_file=DEFAULT_LOG):
    records = []
    if not os.path.exists(log_file):
        return records
    with open(log_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                r["_line"] = idx
                records.append(r)
            except json.JSONDecodeError as e:
                records.append({"_line": idx, "_error": f"invalid json: {e}"})
    return records


def verify_log(log_file=DEFAULT_LOG, chain_file=None, subset=None):
    chain_file = chain_file or os.path.join(os.path.dirname(log_file), "chain.dat")
    prev = ZERO_HASH
    records = subset if subset is not None else read_records(log_file)
    for rec in records:
        line_no = rec.get("_line", "?")
        if "_error" in rec:
            return False, line_no, rec["_error"]
        integrity = rec.get("integrity") or {}
        stored_hash = integrity.get("hash")
        if integrity.get("prev_hash") != prev:
            return False, line_no, "prev_hash mismatch"
        tmp = dict(rec)
        tmp.pop("_line", None)
        tmp["integrity"] = dict(integrity)
        tmp["integrity"].pop("hash", None)
        actual = _hash_record(tmp)
        if actual != stored_hash:
            return False, line_no, "record hash mismatch"
        prev = stored_hash
    if subset is None and os.path.exists(chain_file):
        chain_hashes = [x.strip() for x in open(chain_file, encoding="utf-8") if x.strip()]
        if chain_hashes and chain_hashes[-1] != prev:
            return False, len(records), "chain.dat last hash mismatch"
    return True, None, prev


def filter_records(records, from_ts=None, to_ts=None, level=None, operation=None, serial=None):
    def parse_ts(s):
        if not s: return None
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    start, end = parse_ts(from_ts), parse_ts(to_ts)
    out = []
    for r in records:
        if "_error" in r: continue
        ts = parse_ts(r.get("timestamp"))
        if start and ts and ts < start: continue
        if end and ts and ts > end: continue
        if level and r.get("level") != level: continue
        if operation and r.get("operation") != operation and operation not in r.get("operation", ""): continue
        if serial:
            md = r.get("metadata") or {}
            if str(md.get("serial", "")).upper() != serial.upper(): continue
        out.append(r)
    return out


def print_records(records, fmt="table"):
    if fmt == "json":
        for r in records: r.pop("_line", None)
        print(json.dumps(records, ensure_ascii=False, indent=2))
    elif fmt == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["timestamp", "level", "operation", "status", "message", "metadata"])
        for r in records:
            w.writerow([r.get("timestamp"), r.get("level"), r.get("operation"), r.get("status"), r.get("message"), json.dumps(r.get("metadata", {}), ensure_ascii=False)])
    else:
        print(f"{'Time':<28} {'Level':<8} {'Operation':<24} {'Status':<8} Message")
        print("-" * 100)
        for r in records:
            print(f"{r.get('timestamp',''):<28} {r.get('level',''):<8} {r.get('operation',''):<24} {r.get('status',''):<8} {r.get('message','')}")
