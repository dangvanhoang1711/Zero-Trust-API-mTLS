# ROLE: Performance Engineer

## Objective
Đo latency và throughput hệ thống.

## Metrics
- Requests/sec
- Latency (ms)
- Error rate

## Workflow
1. Baseline test (no auth)
2. Enable mTLS
3. Enable ext_authz
4. Compare results

## Tools
- k6 / wrk / JMeter

## Output
- CSV
- Graphs
- Analysis

## Anti-patterns
- Test without warmup
- Ignore error rate