# SentinelCode Architecture

SentinelCode is a runtime security and verification control plane for
autonomous coding agents.

## High-Level Flow

```text
         Agent
           |
           v
      ToolRequest
           |
           v
     SentinelRuntime
           |
  +------------------+
  |                  |
  v                  v
Policy Engine      Risk Engine
  |                  |
  +--------+---------+
           |
           v
        Decision
           |
           v
     Security Event
           |
           v
  Detection / Analysis
           |
           v
       Verification
```

## Main Components
### Agent
The agent produces tool requests representing actions such as filesystem, shell, and network operations.
### Runtime
SentinelRuntime is the runtime security boundary. It evaluates incoming
tool requests through the policy and risk engines and records the resulting
security event.
### Policy Engine
The policy engine determines whether an action violates the configured
security policy.
### Risk Engine
The risk engine calculates a risk score for the requested action.
### Detection
SentinelCode contains deterministic detectors for several security behaviors,
including:
- Prompt injection
- Sensitive-file access
- Secret exfiltration sequences
- Suspicious shell/network activity
- High-risk package installation
### Security Analysis
The security layer can combine event-level analysis with behavioral analysis.
Gemini integration is available for contextual security analysis.
### Verification
The verification pipeline checks generated projects using:
- Compilation verification
- Test execution
- SAST analysis
- Secret scanning
- Dependency scanning
### Evaluation
SentinelBench provides a controlled evaluation layer over the security
components.
The benchmark currently contains five deterministic scenarios:
1. Prompt injection
2. Sensitive-file access
3. Secret exfiltration
4. High-risk package installation
5. Vulnerable generated code
The evaluation compares baseline behavior with SentinelCode-protected
behavior and stores the measured results as JSON.