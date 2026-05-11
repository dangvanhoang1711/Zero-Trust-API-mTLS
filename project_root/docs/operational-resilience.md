# Operational Resilience

## Overview

This document describes operational resilience testing and recommendations for the Zero-Trust API Authentication system, covering failure scenarios, recovery procedures, and high-availability considerations.

## Tested Resilience Scenarios

### 1. Normal Operation Baseline

**Test**: System operates under normal conditions.

**Verification**:
```bash
docker-compose up --build -d
cd project_root && ./tests/run-all.sh
```

**Expected result**: All tests pass, services healthy.

**Metrics**:
- Request latency: <50ms p95
- Success rate: 100%
- Service availability: 100%

## Untested Scenarios (Future Work)

### 2. Certificate Rotation

**Scenario**: Client certificate expires and must be renewed without service interruption.

**Current state**: Not tested in automated suite.

**Expected behavior**:
1. Client obtains new certificate from CA
2. Client requests new token from Keycloak with new certificate
3. New token contains new `cnf.x5t#S256` thumbprint
4. Client uses new certificate + new token for API calls
5. Old certificate expires, old tokens become invalid

**Failure modes**:
- Client continues using expired certificate → TLS handshake fails
- Client uses new certificate with old token → binding mismatch, `403 Forbidden`

**Recovery**:
- Automated certificate renewal via cert-manager (not implemented)
- Manual certificate renewal and token refresh

**Test plan**:
```bash
# Generate new certificate
openssl req -new -x509 -days 1 -key client.key -out client-new.crt

# Request new token with new certificate
curl --cert client-new.crt --key client.key \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-client-secret" \
  http://localhost:18080/realms/zero-trust/protocol/openid-connect/token

# Verify new token works with new certificate
curl --cert client-new.crt --key client.key \
  -H "Authorization: Bearer $NEW_TOKEN" \
  https://localhost:10000/
```

**Recommendation**: Implement automated testing in `tests/functional/cert-rotation.sh`.

### 3. JWKS Key Rotation

**Scenario**: Keycloak rotates signing keys without service restart.

**Current state**: JWKS cache supports rotation but not tested.

**Expected behavior**:
1. Keycloak generates new signing key
2. Keycloak publishes new key in JWKS endpoint
3. Keycloak signs new tokens with new key (includes new `kid`)
4. ext_authz fetches JWKS on cache miss
5. ext_authz verifies tokens with new key
6. Old tokens remain valid until expiration

**Failure modes**:
- JWKS cache not refreshed → verification fails for new tokens
- Old key removed before old tokens expire → verification fails

**Recovery**:
- Automatic: ext_authz fetches JWKS on unknown `kid`
- Manual: Restart ext_authz to clear cache

**Test plan**:
```bash
# Rotate Keycloak signing key
docker-compose exec keycloak /opt/keycloak/bin/kcadm.sh \
  config credentials --server http://localhost:8080 \
  --realm master --user admin --password admin

docker-compose exec keycloak /opt/keycloak/bin/kcadm.sh \
  update realms/zero-trust -s "attributes.keyRotation=true"

# Request new token (signed with new key)
NEW_TOKEN=$(curl --cert client.crt --key client.key \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-client-secret" \
  http://localhost:18080/realms/zero-trust/protocol/openid-connect/token | jq -r .access_token)

# Verify new token works
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $NEW_TOKEN" \
  https://localhost:10000/
```

**Recommendation**: Implement automated testing in `tests/functional/jwks-rotation.sh`.

### 4. IdP Unavailability

**Scenario**: Keycloak becomes unavailable (network partition, service crash, maintenance).

**Current state**: Not tested.

**Expected behavior**:
1. Keycloak becomes unreachable
2. ext_authz continues using cached JWKS
3. Existing tokens continue to work
4. New token issuance fails (expected)
5. JWKS refresh fails gracefully
6. Service continues operating with cached keys

**Failure modes**:
- JWKS cache expires during outage → verification fails
- No cached keys → all requests fail

**Recovery**:
- Automatic: Keycloak comes back online, JWKS refresh succeeds
- Manual: Restart ext_authz if cache corruption occurs

**Test plan**:
```bash
# Stop Keycloak
docker-compose stop keycloak

# Verify existing tokens still work (cached JWKS)
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $EXISTING_TOKEN" \
  https://localhost:10000/

# Verify new token issuance fails (expected)
curl --cert client.crt --key client.key \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-client-secret" \
  http://localhost:18080/realms/zero-trust/protocol/openid-connect/token

# Restart Keycloak
docker-compose start keycloak
```

**Recommendation**: 
- Implement automated testing in `tests/functional/idp-unavailable.sh`
- Configure JWKS cache TTL > typical outage duration (e.g., 1 hour)
- Monitor JWKS refresh failures and alert

### 5. Replay Cache Failure

**Scenario**: Replay cache becomes unavailable or corrupted.

**Current state**: In-memory cache, no external dependency.

**Expected behavior** (if using Redis):
1. Redis becomes unavailable
2. ext_authz fails to check replay cache
3. System behavior depends on failure mode:
   - **Fail-open**: Allow requests (risk of replay)
   - **Fail-closed**: Deny requests (availability impact)

**Current implementation**: In-memory cache, no external failure mode.

**Future consideration** (Redis deployment):
- Implement circuit breaker for Redis
- Fall back to local cache on Redis failure
- Alert on replay cache unavailability

**Test plan** (future):
```bash
# Stop Redis
docker-compose stop redis

# Verify system behavior (fail-open or fail-closed)
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/

# Restart Redis
docker-compose start redis
```

**Recommendation**: Document desired failure mode before implementing distributed cache.

### 6. ext_authz Service Failure

**Scenario**: ext_authz service crashes or becomes unresponsive.

**Current state**: Single instance, no redundancy.

**Expected behavior**:
1. ext_authz becomes unavailable
2. Envoy cannot authorize requests
3. All API requests fail with `503 Service Unavailable`

**Failure modes**:
- Process crash → Docker restarts container (restart policy: `unless-stopped`)
- Deadlock/hang → Requests timeout
- Memory exhaustion → OOM killer terminates process

**Recovery**:
- Automatic: Docker restart policy
- Manual: `docker-compose restart ext_authz`

**High-availability recommendation**:
- Deploy multiple ext_authz instances
- Use load balancer (Envoy cluster with multiple endpoints)
- Implement health checks
- Configure circuit breaker

**Test plan**:
```bash
# Kill ext_authz
docker-compose kill ext_authz

# Verify requests fail
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/

# Verify Docker restarts service
docker-compose ps ext_authz

# Wait for restart
sleep 5

# Verify requests succeed after restart
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/
```

**Recommendation**: Implement automated testing in `tests/functional/ext-authz-failure.sh`.

### 7. Envoy Proxy Failure

**Scenario**: Envoy proxy crashes or becomes unresponsive.

**Current state**: Single instance, no redundancy.

**Expected behavior**:
1. Envoy becomes unavailable
2. All API requests fail (connection refused)
3. Docker restarts container

**Recovery**:
- Automatic: Docker restart policy
- Manual: `docker-compose restart envoy`

**High-availability recommendation**:
- Deploy multiple Envoy instances behind load balancer
- Use Kubernetes with multiple replicas
- Implement health checks and readiness probes

**Test plan**:
```bash
# Kill Envoy
docker-compose kill envoy

# Verify requests fail
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/

# Verify Docker restarts service
docker-compose ps envoy

# Wait for restart
sleep 5

# Verify requests succeed after restart
curl --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/
```

**Recommendation**: Implement automated testing in `tests/functional/envoy-failure.sh`.

## Monitoring and Alerting Recommendations

### Key Metrics

1. **Request metrics**:
   - Request rate (requests/second)
   - Success rate (%)
   - Error rate by status code (401, 403, 500, 503)
   - Latency (p50, p95, p99)

2. **Authorization metrics**:
   - JWT verification success/failure rate
   - Token-certificate binding success/failure rate
   - Replay cache hit/miss rate
   - JWKS cache hit/miss rate

3. **Service health**:
   - Service uptime
   - Container restart count
   - Memory usage
   - CPU usage

4. **External dependencies**:
   - Keycloak availability
   - JWKS fetch success/failure rate
   - JWKS fetch latency

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Error rate | >1% | >5% |
| Latency p95 | >100ms | >500ms |
| JWKS fetch failures | >5 in 5min | >10 in 5min |
| Service restarts | >2 in 1hr | >5 in 1hr |
| Memory usage | >80% | >95% |

### Recommended Tools

- **Metrics**: Prometheus + Grafana
- **Logging**: ELK stack or Loki
- **Tracing**: Jaeger or Zipkin
- **Alerting**: Alertmanager or PagerDuty

## Backup and Recovery

### Configuration Backup

**Critical configuration**:
- Envoy config: `project_root/envoy_config/envoy.yaml`
- Keycloak realm: `project_root/infra/keycloak/realm-export.json`
- Certificates: `project_root/infra/certs/`
- Docker Compose: `docker-compose.yml`

**Backup procedure**:
```bash
# Create backup directory
mkdir -p backups/$(date +%Y%m%d)

# Backup configuration
cp -r project_root/envoy_config backups/$(date +%Y%m%d)/
cp -r project_root/infra/keycloak backups/$(date +%Y%m%d)/
cp docker-compose.yml backups/$(date +%Y%m%d)/

# Backup certificates (encrypted)
tar czf backups/$(date +%Y%m%d)/certs.tar.gz project_root/infra/certs/
gpg --encrypt --recipient admin@example.com backups/$(date +%Y%m%d)/certs.tar.gz
```

**Recovery procedure**:
```bash
# Restore configuration
cp -r backups/20260511/envoy_config project_root/
cp -r backups/20260511/keycloak project_root/infra/
cp backups/20260511/docker-compose.yml .

# Restore certificates
gpg --decrypt backups/20260511/certs.tar.gz.gpg | tar xzf -

# Restart services
docker-compose up --build -d
```

### State Backup

**Stateful components**:
- Keycloak database (H2 file-based in dev mode)
- Replay cache (in-memory, not persistent)

**Keycloak backup**:
```bash
# Export realm
docker-compose exec keycloak /opt/keycloak/bin/kc.sh export \
  --dir /tmp/export --realm zero-trust

# Copy export
docker cp keycloak:/tmp/export/zero-trust-realm.json \
  backups/$(date +%Y%m%d)/
```

**Keycloak restore**:
```bash
# Copy import file
docker cp backups/20260511/zero-trust-realm.json keycloak:/tmp/import/

# Import realm
docker-compose exec keycloak /opt/keycloak/bin/kc.sh import \
  --file /tmp/import/zero-trust-realm.json
```

## Disaster Recovery

### Recovery Time Objective (RTO)

**Target**: <15 minutes for full service restoration.

**Procedure**:
1. Restore configuration from backup (2 minutes)
2. Restore certificates from backup (1 minute)
3. Start services with `docker-compose up` (5 minutes)
4. Verify services healthy (2 minutes)
5. Run smoke tests (5 minutes)

### Recovery Point Objective (RPO)

**Target**: <1 hour of configuration changes.

**Recommendation**: Automate configuration backup on every change (Git commit).

## Conclusion

The current system has basic resilience through Docker restart policies but lacks comprehensive operational testing and high-availability features. Key recommendations for production:

1. **Implement automated resilience testing** for all scenarios above
2. **Deploy multiple instances** of ext_authz and Envoy with load balancing
3. **Implement distributed replay cache** (Redis) with circuit breaker
4. **Configure monitoring and alerting** for key metrics
5. **Automate backup procedures** for configuration and state
6. **Document runbooks** for common failure scenarios
7. **Conduct regular disaster recovery drills**

The documented scenarios provide a foundation for building a production-ready resilient system.
