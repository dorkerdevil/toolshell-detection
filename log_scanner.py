#!/usr/bin/env python3
"""
IIS W3C Log Scanner for SharePoint ToolShell Chain
Author: Ashish Kunwar (dorkerdevil)

Scans IIS logs for suspicious __VIEWSTATE parameters indicative of exploitation attempts leveraging leaked ValidationKey (CVE-2025-49706 + CVE-2025-49704) enabling malicious ysoserial gadget execution.

Heuristics:
- Very long __VIEWSTATE (>1500 bytes after URL decode)
- High-entropy base64 blobs
- Double base64 patterns
- Presence of gadget class fragments when base64-decoded
- Excessive requests from single IP with varying long VIEWSTATE (spray)

Outputs JSON or CSV with scoring.
"""
import argparse
import base64
import csv
import json
import math
import re
import urllib.parse as up
from collections import defaultdict, Counter
from typing import List, Dict, Any

BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{40,}$')
GADGET_FRAGMENTS = [
    b'TypeConfuseDelegate', b'ObjectDataProvider', b'ActivitySurrogate',
    b'WindowsIdentity', b'TextFormattingRunProperties', b'BinaryFormatter'
]

LOG_FIELD_PREFIX = '#Fields:'


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = Counter(b)
    length = len(b)
    h = 0.0
    for c in freq.values():
        p = c/length
        h -= p * math.log2(p)
    return h


def b64_decode_maybe(val: str):
    s = val.strip()
    pad = (4 - (len(s) % 4)) % 4
    s += '=' * pad
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b''


def analyze_viewstate(v: str) -> Dict[str, Any]:
    raw_len = len(v)
    b64_like = bool(BASE64_RE.match(v))
    decoded = b''
    chain = []
    if b64_like:
        d1 = b64_decode_maybe(v)
        if d1:
            chain.append(f'b64->{len(d1)}')
            decoded = d1
            # try second layer
            if BASE64_RE.match(d1.decode('latin-1', 'ignore')):
                d2 = b64_decode_maybe(d1.decode('latin-1','ignore'))
                if d2:
                    chain.append(f'b64->{len(d2)}')
                    decoded = d2
    ent = entropy(decoded)
    gadgets = []
    if decoded:
        low = decoded.lower()
        for g in GADGET_FRAGMENTS:
            if g.lower() in low:
                gadgets.append(g.decode('latin-1'))
    score = 0
    if raw_len > 1500: score += 2
    if raw_len > 5000: score += 2
    if ent > 5.4: score += 1
    if ent > 5.8: score += 2
    if gadgets: score += min(4, len(gadgets))
    if len(chain) > 1: score += 1
    if score >= 8: risk = 'CRITICAL'
    elif score >=6: risk = 'HIGH'
    elif score >=4: risk = 'MEDIUM'
    elif score >=2: risk = 'LOW'
    else: risk = 'INFO'
    return {
        'raw_length': raw_len,
        'base64_like': b64_like,
        'decode_chain': chain,
        'entropy': round(ent,3),
        'gadgets': gadgets,
        'risk': risk,
        'score': score
    }


def parse_log_line(fields: List[str], line: str) -> Dict[str, str]:
    parts = line.split()
    if len(parts) < len(fields):
        return {}
    return {fields[i]: parts[i] for i in range(len(fields))}


def extract_viewstate_from_uri(uri: str) -> str:
    if '?' not in uri:
        return ''
    qs = uri.split('?',1)[1]
    params = up.parse_qs(qs, keep_blank_values=True)
    if '__VIEWSTATE' in params:
        return params['__VIEWSTATE'][0]
    return ''


def scan_logs(path: str) -> List[Dict[str, Any]]:
    results = []
    fields: List[str] = []
    ip_request_counts = defaultdict(int)
    ip_long_payloads = defaultdict(int)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            if line.startswith('#'):
                if line.startswith(LOG_FIELD_PREFIX):
                    fields = line[len(LOG_FIELD_PREFIX):].strip().split()
                continue
            if not fields:
                continue
            rec = parse_log_line(fields, line)
            if not rec:
                continue
            uri = rec.get('cs-uri-stem','')
            query = rec.get('cs-uri-query','')
            full_uri = uri
            if query and query != '-':
                full_uri = f"{uri}?{query}"
            vs = extract_viewstate_from_uri(full_uri)
            if not vs:
                continue
            ip = rec.get('c-ip','unknown')
            ip_request_counts[ip]+=1
            decoded_vs = up.unquote_plus(vs)
            analysis = analyze_viewstate(decoded_vs)
            if analysis['raw_length']>1500:
                ip_long_payloads[ip]+=1
            results.append({
                'source_ip': ip,
                'date': rec.get('date',''),
                'time': rec.get('time',''),
                'uri': uri,
                'analysis': analysis
            })
    # Add spray heuristic annotation
    for r in results:
        ip = r['source_ip']
        spray_ratio = 0
        if ip_request_counts[ip]:
            spray_ratio = ip_long_payloads[ip]/ip_request_counts[ip]
        r['spray_indicator'] = spray_ratio > 0.3 and ip_long_payloads[ip] >= 5
    return results


def main():
    ap = argparse.ArgumentParser(description='IIS log scanner for malicious SharePoint __VIEWSTATE exploitation attempts')
    ap.add_argument('-l','--log', required=True, help='Path to IIS W3C log file')
    ap.add_argument('-j','--json', action='store_true', help='Output JSON')
    ap.add_argument('-c','--csv', help='Output CSV file path')
    ap.add_argument('--min-risk', default='INFO', help='Minimum risk to display (INFO,LOW,MEDIUM,HIGH,CRITICAL)')
    args = ap.parse_args()
    order = ['INFO','LOW','MEDIUM','HIGH','CRITICAL']
    try:
        min_idx = order.index(args.min_risk.upper())
    except ValueError:
        print('Invalid --min-risk value')
        return
    results = scan_logs(args.log)
    filtered = [r for r in results if order.index(r['analysis']['risk']) >= min_idx]
    if args.json:
        print(json.dumps(filtered, indent=2))
    else:
        for r in filtered:
            a = r['analysis']
            print(f"{r['date']} {r['time']} {r['source_ip']} {r['uri']} risk={a['risk']} score={a['score']} len={a['raw_length']} gadgets={','.join(a['gadgets']) or '-'} spray={r['spray_indicator']}")
    if args.csv:
        with open(args.csv,'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['date','time','ip','uri','risk','score','len','entropy','gadgets','spray'])
            for r in filtered:
                a = r['analysis']
                w.writerow([r['date'], r['time'], r['source_ip'], r['uri'], a['risk'], a['score'], a['raw_length'], a['entropy'], ';'.join(a['gadgets']), r['spray_indicator']])

if __name__ == '__main__':
    main()
