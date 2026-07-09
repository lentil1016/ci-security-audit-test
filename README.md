# ci-security-audit-test

PoC for CI security audit with three-level response mechanism:
- **BLOCK**: immediately dangerous → pipeline stops
- **WARN**: long-term risk → PR comment, pipeline continues
- **PASS**: all clear
