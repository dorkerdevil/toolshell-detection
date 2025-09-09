# SharePoint ToolShell Chain Detection 

This repo helps defenders spot and triage attacks using the SharePoint ToolShell chain (CVE-2025-49706 + CVE-2025-49704). Attackers are actively exploiting this to run code on SharePoint servers by forging signed __VIEWSTATE payloads after stealing the ValidationKey.

## What’s going on?
If an attacker gets the ValidationKey (via memory dump or config leak), they can use ysoserial to generate malicious ViewState payloads. These are signed and accepted by SharePoint, leading to remote code execution. This is happening in the wild right now (see Ars Technica, Sept 2025).

## CVEs
- CVE-2025-49706: ValidationKey/machineKey leak
- CVE-2025-49704: Allows forged signed ViewState to be accepted

## How detection works
You can’t just check the signature—attackers have the real key. Instead, look for:
- Very large __VIEWSTATE values (often thousands of bytes)
- Double base64 encoding, high entropy
- Gadget/class names inside decoded payloads (TypeConfuseDelegate, etc)
- Bursts of big ViewState requests from one IP
- Known ysoserial .NET gadget markers

## What’s in this repo?
| File | What it does |
|------|--------------|
| viewstate_analyzer.py | Checks ViewState blobs for risky signs (entropy, gadgets, etc) |
| log_scanner.py | Scans IIS logs for suspicious ViewState requests |
| sigma_toolshell_viewstate.yaml | Sigma rule for SIEMs (tune length logic as needed) |
| suricata_http_viewstate.rules | Suricata rule for long ViewState in HTTP traffic |
| patterns_yososerial_markers.txt | Gadget marker strings |

## Usage
### Analyze a single payload
```bash
python viewstate_analyzer.py --payload "<BASE64_VIEWSTATE_STRING>" --json
```

### Batch from file
```bash
python viewstate_analyzer.py -f samples.txt --min-risk MEDIUM
```

### Pipe from another tool
```bash
cat harvested_viewstates.txt | python viewstate_analyzer.py -j --min-risk HIGH
```

### Scan IIS logs
```bash
python log_scanner.py -l u_ex250909.log --json --min-risk MEDIUM > findings.json
python log_scanner.py -l u_ex250909.log --csv findings.csv --min-risk HIGH
```

Make sure IIS logs include cs-uri-query. If not, enable it and restart logging.

## Example attack (for context)
```
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -nop -c \"dir 'C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\15\\TEMPLATE\\LAYOUTS'\"" \
  --generator="<ID>" --validationkey="<LEAKED_VALIDATION_KEY>" --validationalg="SHA1" --islegacy --minify
```
Then send to:
```
https://target/_layouts/15/anything.aspx?__VIEWSTATE=<MALICIOUS>
```

## Output fields
- raw_length / final_length: Size before/after decode
- entropy: Shannon entropy (compressed/packed is >5.5)
- gadgets: Gadget markers found
- losformatter_likely: Heuristic for LosFormatter structure
- risk / score: Severity

## Triage tips
- CRITICAL: Isolate server, dump w3wp.exe memory
- HIGH: Check for process creation (Sysmon Event ID 1, 5)
- MEDIUM: Compare to normal app behavior

## Hunt ideas
- Look for long ViewState with few User-Agent types (automation)
- Sequence of failed then successful long payloads
- After exploit: PowerShell, certutil, msbuild spawned by w3wp.exe

## Extending Sigma
Tune backend to alert on length >1500 chars and entropy >5.4.

## Suricata
Add suricata_http_viewstate.rules to your custom rules. Needs HTTP body inspection or SSL MITM (if legal).

## Limitations
- Signed malicious payloads look like legit big ViewState
- Gadget markers may be missing if attacker uses binary formatter chain
- High entropy can cause false positives

## Mitigation
- Patch for CVE-2025-49706 / CVE-2025-49704
- Rotate ValidationKey/machineKey after incident
- Restrict w3wp.exe process execution (AppLocker/WDAC)
- Enable Sysmon (Event ID 1, 5, 7, 11)
- Watch for exfil in query strings

## Sample JSON output
```json
[
  {
    "source": "samples.txt:3",
    "raw_length": 2104,
    "decode_chain": ["base64 decoded length=1580"],
    "final_length": 1580,
    "entropy": 5.86,
    "gadgets": ["TypeConfuseDelegate","BinaryFormatter"],
    "losformatter_likely": true,
    "risk": "HIGH",
    "score": 7
  }
]
```

---
**Author:** Ashish Kunwar (dorkerdevil)

This repo is for defenders and blue teams. If you use it, credit is appreciated. Pull requests welcome.

