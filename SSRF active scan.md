

## 1.Server Side Request Forgery (SSRF) Vulnerabilty Detection Active Rules

### 1.1 Out Of Band (OBB) Detection
#### 1.1.a Idea
- OBB Method: `DNS` and `HTTP`
- Payloads: `[ssrf-id.attacker.com,http(s)://ssrf-id.attacker.com/ssrf-id-poc.txt]`
- Positive detection: `DNS` or `HTTP` query string `ssrf-id`occurs in attacker server's log  
#### 1.1.b Implementation

### 1.2 Signature-Based Detection
- Payloads: `[127.0.0.1, localhost, http://127.0.0.1:21, http://127.0.0.1:1234]`
- Positive detection: Error-indicated strings occur in the response. Example:  `Connection refused`

### 1.3 Heuristic-Based Detection:
- Technique: Compare Response Difference with difference payload
