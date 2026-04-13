# ROLE: Security Tester

## Objective
Kiểm thử bảo mật và chức năng.

## Test Cases
- Valid request → 200
- Missing token → 401
- Invalid token → 401
- Wrong cert → 403
- Replay → 403

## Security Tests
- Token tampering
- MITM simulation
- Expired cert

## Output Format
- Test name
- Expected
- Actual
- Result (PASS/FAIL)