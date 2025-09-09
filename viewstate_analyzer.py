#!/usr/bin/env python3
"""
SharePoint ToolShell Chain VIEWSTATE Analyzer
Author: Ashish Kunwar (dorkerdevil)

Detects potentially malicious __VIEWSTATE payloads crafted after leakage of ValidationKey (CVE-2025-49706 + CVE-2025-49704 chain) enabling ysoserial gadget execution.

Features:
- Base64 (and double-Base64) decode with padding auto-fix
- Optional decompression (GZip / Deflate) detection
- ASP.NET LosFormatter structure probing (lightweight heuristic)
- Gadget marker scan (TypeConfuseDelegate, ObjectDataProvider, ActivitySurrogate, WindowsIdentity, DataSet, TextFormattingRunProperties)
- Size / entropy thresholds
- Signature scoring model producing risk levels (LOW/MED/HIGH/CRITICAL)
- JSON + table output
- Batch file / stdin / single payload modes
- YSoSerial .NET gadget fingerprint heuristics (class name fragments)

NOTE: This does not re-implement full ASP.NET ViewState validation; it provides triage indicators.
"""

import argparse
import base64
import binascii
import gzip
import io
import json
import math
import os
import re
import sys
import zlib
from typing import Any, Dict, List, Optional, Tuple

GADGET_MARKERS = [
    b'TypeConfuseDelegate',
    b'ObjectDataProvider',
    b'ActivitySurrogate',
    b'WindowsIdentity',
    b'TextFormattingRunProperties',
    b'DataSet',
    b'BinaryFormatter',
    b'Cmd /c',
    b'PowerShell',
]

BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{20,}$')

def fix_padding(s: str) -> str:
    rem = len(s) % 4
    if rem:
        s += '=' * (4 - rem)
    return s

def b64_try(data: str) -> Optional[bytes]:
    data = data.strip().replace('\n', '')
    try:
        return base64.b64decode(fix_padding(data), validate=False)
    except Exception:
        return None

def maybe_double_b64(raw: str) -> Tuple[bytes, List[str]]:
    notes = []
    first = b64_try(raw)
    if not first:
        raise ValueError('Not base64-like')
    notes.append('base64 decoded length=%d' % len(first))
    if BASE64_RE.match(first.decode('latin-1', 'ignore')):
        second = b64_try(first.decode('latin-1', 'ignore'))
        if second:
            notes.append('double base64 decoded length=%d' % len(second))
            return second, notes
    return first, notes

def try_decompress(buf: bytes) -> Tuple[bytes, List[str]]:
    notes = []
    # GZip
    if buf.startswith(b'\x1f\x8b'):
        try:
            dec = gzip.decompress(buf)
            notes.append('gzip decompressed -> %d bytes' % len(dec))
            return dec, notes
        except Exception:
            pass
    # Deflate (zlib header 0x78 0x9c or other common)
    if buf.startswith(b'\x78'):
        try:
            dec = zlib.decompress(buf)
            notes.append('zlib decompressed -> %d bytes' % len(dec))
            return dec, notes
        except Exception:
            pass
    return buf, notes

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b]+=1
    entropy = 0.0
    length = len(data)
    for c in freq:
        if c:
            p = c/length
            entropy -= p * math.log2(p)
    return entropy

LOSFORMATTER_PATTERNS = [
    # Rough fragments that often appear after formatting: ViewState MAC block, serialization tokens.
    b'\xff\x01',  # Serialization header marker often at start
    b'\xff\x1f',
    b'\x00System.',
    b'TypeName',
]


def losformatter_likely(data: bytes) -> bool:
    hits = 0
    for pat in LOSFORMATTER_PATTERNS:
        if pat in data:
            hits += 1
    return hits >= 2


def scan_gadgets(data: bytes) -> List[str]:
    found = []
    ldata = data
    for marker in GADGET_MARKERS:
        if marker.lower() in ldata.lower():
            found.append(marker.decode('latin-1'))
    # simple pattern for powershell -enc argument base64 stub
    if re.search(br'powershell\s+-nop', data, re.IGNORECASE):
        found.append('PowerShell Inline Command')
    return sorted(set(found))


def score(payload_len: int, entropy: float, gadgets: List[str], los_like: bool) -> Tuple[str, int]:
    s = 0
    if payload_len > 1500:
        s += 2
    if payload_len > 5000:
        s += 2
    if entropy > 5.2:
        s += 1
    if entropy > 5.8:
        s += 2
    if gadgets:
        s += min(4, len(gadgets))
    if los_like:
        s += 2
    # Map numeric to label
    if s >= 8:
        return 'CRITICAL', s
    if s >= 6:
        return 'HIGH', s
    if s >= 4:
        return 'MEDIUM', s
    if s >= 2:
        return 'LOW', s
    return 'INFO', s


def analyze_viewstate(raw: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'raw_length': len(raw),
        'base64_like': bool(BASE64_RE.match(raw.strip().replace('\n',''))),
        'decode_chain': [],
        'errors': [],
    }
    try:
        decoded, notes = maybe_double_b64(raw)
        result['decode_chain'].extend(notes)
    except Exception as e:
        result['errors'].append(str(e))
        return result

    decompressed, dnotes = try_decompress(decoded)
    if dnotes:
        result['decode_chain'].extend(dnotes)

    ent = shannon_entropy(decompressed)
    gadgets = scan_gadgets(decompressed)
    los_like = losformatter_likely(decompressed)
    risk_label, score_val = score(len(decompressed), ent, gadgets, los_like)

    result.update({
        'final_length': len(decompressed),
        'entropy': round(ent, 3),
        'gadgets': gadgets,
        'losformatter_likely': los_like,
        'risk': risk_label,
        'score': score_val,
    })
    # Provide small preview (printable)
    try:
        preview = decompressed[:160]
        result['printable_preview'] = preview.decode('utf-8', 'ignore')
    except Exception:
        result['printable_preview'] = ''
    return result


def iter_inputs(args) -> List[Tuple[str, str]]:
    items: List[Tuple[str,str]] = []
    if args.payload:
        items.append(('cli', args.payload))
    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                line=line.strip()
                if not line:
                    continue
                items.append((f'{args.file}:{i}', line))
    if not sys.stdin.isatty():
        for i, line in enumerate(sys.stdin, 1):
            line=line.strip()
            if line:
                items.append((f'stdin:{i}', line))
    return items


def main():
    p = argparse.ArgumentParser(description='SharePoint ToolShell __VIEWSTATE Analyzer')
    p.add_argument('-p','--payload', help='Single __VIEWSTATE payload string')
    p.add_argument('-f','--file', help='File containing one payload per line')
    p.add_argument('-j','--json', action='store_true', help='Output JSON array of results')
    p.add_argument('--min-risk', default='INFO', help='Only show results >= this risk (INFO,LOW,MEDIUM,HIGH,CRITICAL)')
    args = p.parse_args()

    order = ['INFO','LOW','MEDIUM','HIGH','CRITICAL']
    try:
        min_idx = order.index(args.min_risk.upper())
    except ValueError:
        print('Invalid --min-risk value', file=sys.stderr)
        sys.exit(2)

    inputs = iter_inputs(args)
    if not inputs:
        print('No input provided. Use --payload or --file or pipe data.', file=sys.stderr)
        sys.exit(1)

    results = []
    for src, raw in inputs:
        res = analyze_viewstate(raw)
        res['source'] = src
        results.append(res)

    if args.json:
        # filter
        filt = [r for r in results if order.index(r.get('risk','INFO')) >= min_idx]
        print(json.dumps(filt, indent=2))
        return

    # Text table output
    print(f"Analyzed {len(results)} payload(s)\n")
    for r in results:
        if order.index(r.get('risk','INFO')) < min_idx:
            continue
        print(f"[{r['risk']}] {r['source']} score={r.get('score')} len={r.get('final_length')} entropy={r.get('entropy')} gadgets={','.join(r.get('gadgets', [])) or '-'}")
        if r.get('decode_chain'):
            print('  decode:', ' | '.join(r['decode_chain']))
        if r.get('errors'):
            print('  errors:', '; '.join(r['errors']))
        if r.get('printable_preview'):
            preview = r['printable_preview'].replace('\n',' ')[:120]
            print('  preview:', preview)
        print()

if __name__ == '__main__':
    main()
