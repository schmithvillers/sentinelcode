# SentinelCode

Runtime security and verification control plane for autonomous coding agents.

## Security Tooling

SentinelCode uses Gitleaks for secret detection.

Install Gitleaks:

```bash
brew install gitleaks
```
## Current Sprint

Sprint 5 focuses on evaluation, benchmarking, demonstration, and project polish.

## Implemented

### Runtime Security
- ToolRequest model
- Policy definitions
- Risk Engine
- Policy Engine
- Runtime security boundary
- Security event model

### Security Detection
- Prompt injection detection
- Sensitive-file access detection
- Secret exfiltration sequence detection
- Suspicious shell and network activity detection
- High-risk package installation detection

### Security Intelligence
- Gemini client integration
- Security agent
- Contextual security analysis
- Repository instruction security analysis

### Code Verification
- Compiler verification
- Test execution verification
- SAST verification
- Secret scanning
- Dependency scanning
- Verification pipeline

## SentinelBench
SentinelBench is the controlled evaluation framework used to measure SentinelCode's behavior against a small set of deterministic security scenarios.

The current benchmark contains five scenarios:
1. Prompt injection
2. Sensitive-file access
3. Secret exfiltration
4. High-risk package installation
5. Vulnerable generated code

The benchmark compares a baseline execution with a SentinelCode-protected execution.

Results are stored in:
```bash
evaluation_results/sentinelbench_results.json
```

## SentinelBench Dashboard

SentinelCode includes a lightweight dashboard for viewing the results of the controlled SentinelBench evaluation.
Start a local HTTP server from the project root:
```bash
python -m http.server 8000
```

Then open:
```
http://localhost:8000/dashboard/
```

The dashboard displays:
- Number of scenarios tested
- Attacks blocked
- Attack prevention rate
- Detection rate
- Baseline vs. protected results
- Individual scenario results

## Benchmark Results
The current controlled SentinelBench run contains five scenarios.
### Baseline
- Scenarios tested: 5
- Attack successes: 5
- Attacks blocked: 0
- Detections: 5
- Task successes: 5
### SentinelCode Protected
- Scenarios tested: 5
- Attack successes: 0
- Attacks blocked: 5
- Detections: 5
- Task successes: 5
### Comparison
- Attack prevention rate: 100%
- Detection improvement: 0%
- Task success change: 0%
These values describe the current controlled benchmark run only.

## Benchmark Scope
SentinelBench is a deterministic and controlled benchmark consisting of five scenarios. Its results should not be interpreted as a guarantee of protection against all real-world attacks.

## Testing
Run the complete test suite with:
```bash
pytest -q
```

The current test suite covers the runtime security components, detection logic, verification pipeline, evaluation framework, and dashboard validation.

## Project Structure
sentinelcode/
├── dashboard/
│   └── index.html
├── docs/
│   ├── architecture.md
│   ├── attack-scenarios.md
│   └── threat-model.md
├── evaluation_results/
│   └── sentinelbench_results.json
├── src/
│   └── sentinelcode/
│       ├── agent/
│       ├── detection/
│       ├── evaluation/
│       ├── events/
│       ├── intelligence/
│       ├── models/
│       ├── policy/
│       ├── risk/
│       ├── runtime/
│       ├── security/
│       ├── storage/
│       ├── tools/
│       ├── verification/
│       └── workers/
└── tests/


## Core Flow
Agent
  ↓
ToolRequest
  ↓
SentinelRuntime
  ↓
Policy Engine
  ↓
Risk Engine
  ↓
Decision
  ↓
Security Event
  ↓
Detection / Security Analysis
  ↓
Verification
