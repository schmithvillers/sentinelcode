# SentinelCode Threat Model

SentinelCode focuses on controlling potentially dangerous actions performed
by autonomous coding agents.

## Protected Surfaces

### Filesystem

Potentially dangerous filesystem operations include:

- Reading `.env` files
- Reading SSH keys
- Reading credential files
- Accessing other sensitive files

Normal source-code operations remain part of the expected development
workflow.

### Shell

Shell commands can be used for legitimate development tasks but can also
perform dangerous operations.

Examples of monitored or restricted behavior include:

- Destructive system commands
- Privileged commands
- High-risk package installation
- Commands involved in suspicious action sequences

### Network

Network access can be required for legitimate development tasks but can also
be used to transfer sensitive information.

SentinelCode analyzes network activity in combination with preceding agent
actions to identify suspicious sequences such as sensitive-file access
followed by network activity.

## Threat Categories

The current SentinelBench evaluation covers:

| Scenario | Threat |
|---|---|
| PI-001 | Prompt injection |
| SF-001 | Sensitive-file access |
| EX-001 | Secret exfiltration |
| PK-001 | High-risk package installation |
| VC-001 | Vulnerable generated code |

## Security Controls

SentinelCode uses multiple layers of control:

1. **Policy enforcement** — evaluates whether a requested action violates
   configured policy.
2. **Risk assessment** — calculates a risk score for requested actions.
3. **Behavior detection** — analyzes security events and action sequences.
4. **Security analysis** — provides contextual analysis of security events.
5. **Code verification** — checks generated projects using compilation,
   tests, SAST, secret scanning, and dependency scanning.

## Limitations

SentinelCode's current SentinelBench evaluation is intentionally controlled
and deterministic.

The benchmark demonstrates the behavior of the implemented security
controls against the five selected scenarios. It does not establish complete
protection against every possible attack or unsafe behavior an autonomous
coding agent could encounter.