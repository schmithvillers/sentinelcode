# SentinelCode

Runtime security and verification control plane for autonomous coding agents.

## Current Sprint

Sprint 1 complete:

Implemented:

- ToolRequest model
- Policy definitions
- Risk Engine
- Policy Engine
- Runtime security boundary
- Security event model

Current flow:

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
### Sprint 1 : Tests

platform darwin -- Python 3.11.1, pytest-9.1.1, pluggy-1.6.0
configfile: pyproject.toml
testpaths: tests
collected 24 items                                                  

tests/test_decision.py .                                      [  4%]
tests/test_policy.py ..                                       [ 12%]
tests/test_policy_engine.py ......                            [ 37%]
tests/test_risk.py .......                                    [ 66%]
tests/test_runtime.py ..                                      [ 75%]
tests/test_security_event.py .                                [ 79%]
tests/test_tool_request.py .                                  [ 83%]
tests/test_tools.py ....                                      [100%]

======================== 24 passed in 0.04s =========================
