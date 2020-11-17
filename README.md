

## 1.Server Side Request Forgery (SSRF) Vulnerabilty Detection Active Rules
### 1.1 Out Of Band (OBB) Detection
- Method `DNS` and `HTTP`
- payload: `ssrf-id.attacker.com`, `http(s)://ssrf-id.attacker.com/ssrf-id-poc.txt`
- positive detection: `DNS` or `HTTP` query string `ssrf-id`occurs in attacker server's log  
