# nox-plugin-risk-register

**Automated technical risk identification and categorization for codebases.**

## Overview

`nox-plugin-risk-register` is a Nox security scanner plugin that identifies and categorizes technical risks across your codebase. It goes beyond vulnerability detection to surface structural risks: security-related technical debt, deprecated API usage, single points of failure, missing error recovery mechanisms, and excessive code complexity.

Traditional security scanners focus on exploitable vulnerabilities. Risk registers focus on conditions that increase the likelihood and impact of future incidents. A database connection without pooling or fallback is not a vulnerability today, but it becomes a critical single point of failure during an outage. A function with 200 lines and 6 levels of nesting is not insecure, but it is where bugs -- including security bugs -- hide.

This plugin scans Go, Python, JavaScript, TypeScript, Java, Ruby, and C# source files. It produces findings across five risk categories, each with metadata for risk classification and tracking. All analysis is deterministic, offline, and read-only.

## Use Cases

### Building an Engineering Risk Register

Your CTO needs a quarterly risk register that inventories technical risks across the codebase. The plugin scans all repositories and produces categorized findings -- technical debt, deprecated APIs, single points of failure, missing resilience patterns, and complexity hotspots -- that feed directly into a risk register spreadsheet or GRC platform.

### Identifying Resilience Gaps Before Production

Your SRE team is preparing for a production launch and needs to verify that the application handles failures gracefully. The plugin detects database connections without pooling or fallback, external service calls without retry or circuit breaker mechanisms, and flags these as single points of failure that must be addressed before go-live.

### Prioritizing Technical Debt with Security Impact

Your engineering team has thousands of TODO and FIXME comments. The plugin filters for the ones that matter most: comments that reference security, authentication, cryptography, passwords, tokens, or vulnerabilities. These security-related debt markers represent deferred risk that should be prioritized above routine tech debt.

### Enforcing API Deprecation Policies

Your organization wants to ensure that deprecated APIs (Go's `ioutil`, Python 2 patterns, JavaScript's `document.write`) are not used in new code. The plugin detects deprecated API usage across multiple languages and flags it as a medium-severity risk, giving teams a clear inventory of modernization work.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-risk-register
   ```

2. **Create a test project with technical risks**

   ```bash
   mkdir -p demo-risk && cd demo-risk

   cat > server.go <<'EOF'
   package main

   import (
       "database/sql"
       "encoding/json"
       "io/ioutil"
       "net/http"
   )

   // TODO: fix authentication bypass for admin endpoints - security risk
   func handleRequest(db *sql.DB, w http.ResponseWriter, r *http.Request) {
       conn, _ := sql.Open("postgres", "host=localhost")

       resp, _ := http.Get("https://api.external.com/data")
       body, _ := ioutil.ReadAll(resp.Body)

       var data map[string]interface{}
       json.Unmarshal(body, &data)

       // ... 60 more lines of deeply nested business logic ...
       if r.Method == "POST" {
           if data["type"] == "order" {
               if data["amount"] != nil {
                   if data["currency"] == "USD" {
                       if data["status"] == "pending" {
                           // process order
                       }
                   }
               }
           }
       }
   }
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/risk-register demo-risk/
   ```

4. **Review findings**

   ```
   nox/risk-register scan completed: 4 findings

   RISK-001 [HIGH] Security-related technical debt:
       // TODO: fix authentication bypass for admin endpoints - security risk
     Location: demo-risk/server.go:10
     Confidence: medium
     Risk Type: tech_debt

   RISK-002 [MEDIUM] Deprecated API usage detected (Go deprecated API): ioutil.ReadAll(resp.Body)
     Location: demo-risk/server.go:15
     Confidence: high
     Risk Type: deprecated_api

   RISK-003 [HIGH] Single point of failure: database connection without pooling or fallback mechanism
     Location: demo-risk/server.go:12
     Confidence: high
     Risk Type: single_point_of_failure
     Resource: database

   RISK-004 [MEDIUM] External service calls detected without retry or circuit breaker mechanism
     Location: demo-risk/server.go:14
     Confidence: medium
     Risk Type: missing_recovery
   ```

## Rules

| Rule ID  | Description | Severity | Confidence | CWE |
|----------|-------------|----------|------------|-----|
| RISK-001 | Security-related technical debt: TODO, FIXME, HACK, or XXX comments referencing security, auth, cryptography, passwords, secrets, tokens, vulnerabilities, injection, XSS, CSRF, sanitization, or privileges | High | Medium | -- |
| RISK-002 | Deprecated API usage: Go (`ioutil`, `x509.ParseCRL`, `md5.New`, `sha1.New`, `des.NewCipher`), Python (`md5`, `sha`, `has_key`, `raw_input`, `execfile`), JavaScript (`document.write`, `escape`, `__proto__`, `Object.observe`, `.substr`) | Medium | High | -- |
| RISK-003 | Single point of failure: database connection detected without connection pooling or fallback/failover mechanism | High | High | -- |
| RISK-004 | Missing error recovery: external service calls detected without retry, backoff, or circuit breaker mechanism | Medium | Medium | -- |
| RISK-005 | Code complexity: functions exceeding 50 lines or conditional nesting depth of 4+ levels | Low | High | -- |

## Supported Languages / File Types

| Language | Extensions |
|----------|-----------|
| Go | `.go` |
| Python | `.py` |
| JavaScript | `.js`, `.jsx` |
| TypeScript | `.ts`, `.tsx` |
| Java | `.java` |
| Ruby | `.rb` |
| C# | `.cs` |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/risk-register --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-risk-register
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-risk-register.git
cd nox-plugin-risk-register
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-risk-register .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions across seven languages.

2. **Per-File Analysis**: Each source file is scanned line by line for:
   - **RISK-001**: Security-related TODO/FIXME/HACK/XXX comments via regex matching
   - **RISK-002**: Language-specific deprecated API patterns
   - **RISK-005**: Function length tracking and conditional nesting depth measurement

3. **Workspace-Level Risk Context**: The scanner tracks workspace-wide indicators:
   - Database connections vs. pooling/fallback mechanisms (RISK-003)
   - External service calls vs. retry/circuit-breaker mechanisms (RISK-004)
   - These are emitted as workspace-level findings after all files are scanned

4. **Complexity Measurement**: Function boundaries are detected via language-aware regex patterns. Line count and nesting depth (measured by indentation level) are tracked per function. Functions exceeding 50 lines or nesting depth of 4+ levels generate findings.

All analysis is deterministic, offline, and read-only.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-risk-register).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
