<!-- What can an autonomous coding agent do that could become dangerous?

1. Filesystem
- Normal source files → allowed
- .env → blocked
- SSH keys → blocked
- System files → blocked
2. Shell
- pytest → allowed
- git status → allowed
- git diff → allowed
- rm -rf / → blocked
- sudo ... → blocked
3. Network
- Approved development domains → allowed
- Unknown external domains → blocked-->