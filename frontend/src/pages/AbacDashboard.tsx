import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getToken, logout, isAuthenticated } from '../services/auth';
import api from '../services/api';

interface PolicyMatch {
  path?: string;
  path_prefix?: string;
  methods?: string[];
}

interface PolicyConditions {
  required_scopes?: string[];
  token_subjects?: string[];
  cert_subjects?: string[];
  claims?: Record<string, string[]>;
  constraint?: unknown;
}

interface ConditionDetail {
  fact: string;
  operator: string;
  expected: unknown;
  actual: unknown;
  result: boolean;
}

interface PolicyRule {
  name: string;
  match: PolicyMatch;
  conditions: PolicyConditions;
  action: string;
  userMatch: boolean;
  conditionDetails: ConditionDetail[];
}

interface PolicyResponse {
  version: string;
  default_action: string;
  rules: PolicyRule[];
  user: {
    sub?: string;
    iss?: string;
    aud?: string | string[];
    roles: string[];
    relevantRoles: string[];
    privilege: string;
    preferred_username?: string;
    email?: string;
    emailVerified?: boolean;
  };
}

interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  scope?: string;
  email?: string;
  email_verified?: boolean;
  realm_access?: { roles: string[] };
  preferred_username?: string;
  [key: string]: unknown;
}

function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1])) as JwtPayload;
  } catch {
    return null;
  }
}

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function getVietnamTime() {
  // Always compute in Asia/Ho_Chi_Minh (UTC+7) to match backend evaluation
  const now = new Date();
  const vnStr = now.toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' });
  const vn = new Date(vnStr);
  return {
    hour: vn.getHours(),
    dayOfWeek: vn.getDay(),         // 0=Sun … 6=Sat
    dayName: DAY_NAMES[vn.getDay()],
    timeStr: now.toLocaleTimeString('en-US', {
      timeZone: 'Asia/Ho_Chi_Minh',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }),
    isWeekend: vn.getDay() === 0 || vn.getDay() === 6,
  };
}

function friendlyFact(fact: string): string {
  const map: Record<string, string> = {
    'token.sub': 'JWT Subject',
    'token.realm_access.roles': 'User Roles',
    'token.email': 'Email',
    'request.time.hour': 'Current Hour',
    'request.time.day_of_week': 'Day of Week',
    'cert.subject': 'Client Cert Subject',
    'token.scope': 'OAuth Scopes',
  };
  return map[fact] ?? fact;
}

function formatActual(fact: string, actual: unknown): string {
  if (actual === null || actual === undefined) return '—';
  if (fact === 'request.time.hour') return `${actual}h`;
  if (fact === 'request.time.day_of_week') {
    const d = Number(actual);
    return `${DAY_NAMES[d] ?? d} (${d})`;
  }
  if (Array.isArray(actual)) {
    if (actual.length > 0 && actual.every(a => typeof a === 'boolean')) {
      return actual.map(a => a ? '✓' : '✗').join(', ');
    }
    return actual.join(', ');
  }
  return String(actual);
}

function formatExpected(fact: string, operator: string, expected: unknown): string {
  if (expected === null || expected === undefined) return '—';
  if (fact === 'request.time.day_of_week' && Array.isArray(expected)) {
    return expected.map((d: string | number) => `${DAY_NAMES[Number(d)] ?? d} (${d})`).join(', ');
  }
  if (fact === 'request.time.hour' && operator === 'between' && Array.isArray(expected) && expected.length === 2) {
    return `${expected[0]}h – ${expected[1]}h`;
  }
  if (fact === 'request.time.hour' && operator === 'not between' && Array.isArray(expected) && expected.length === 2) {
    return `${expected[0]}h – ${expected[1]}h`;
  }
  if (Array.isArray(expected)) return expected.join(', ');
  return String(expected);
}

function friendlyOperator(op: string): string {
  const map: Record<string, string> = {
    'contains': 'contains',
    'not contains': 'does NOT contain',
    'in': 'in',
    'not in': 'NOT in',
    'exists': 'exists',
    'not exists': 'does NOT exist',
    'matches': 'matches',
    'not matches': 'does NOT match',
    'between': 'between',
    'not between': 'NOT between',
    'eq': '=',
    'neq': '≠',
  };
  return map[op] ?? op;
}

export default function AbacDashboard() {
  const navigate = useNavigate();
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [rawToken, setRawToken] = useState<string | null>(null);
  const [jwtPayload, setJwtPayload] = useState<JwtPayload | null>(null);
  const [showRawToken, setShowRawToken] = useState(false);
  const [error, setError] = useState('');
  const ctx = getVietnamTime();

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
      return;
    }
    const token = getToken();
    if (token) {
      setRawToken(token);
      setJwtPayload(decodeJwt(token));
    }
  }, [navigate]);

  const fetchPolicies = useCallback(async () => {
    try {
      const data = await api.get<PolicyResponse>('/api/abac/policies');
      setPolicy(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated()) {
      fetchPolicies();
    }
  }, [fetchPolicies]);

  const userRoles = policy?.user?.roles ?? jwtPayload?.realm_access?.roles ?? [];
  const matchCount = policy?.rules?.filter(r => r.userMatch).length ?? 0;
  const totalRules = policy?.rules?.length ?? 0;
  const isPrivilegeHigh = (policy?.user?.privilege ?? 'LOW') === 'HIGH';

  return (
    <>
      <div className="card" style={{ borderLeft: `4px solid ${isPrivilegeHigh ? '#dc2626' : '#16a34a'}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <h2 style={{ margin: 0 }}>ABAC Dashboard</h2>
            <span className={`badge badge-privilege-${isPrivilegeHigh ? 'high' : 'low'}`}>
              {isPrivilegeHigh ? 'ADMIN PRIVILEGE' : 'STANDARD USER'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-secondary" onClick={fetchPolicies}>Refresh</button>
            <button className="btn btn-danger" onClick={() => { logout(); navigate('/login'); }}>
              Logout
            </button>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid #f3f4f6' }}>
          <div>
            <div className="stat-label">User</div>
            <strong>{policy?.user?.preferred_username ?? jwtPayload?.preferred_username ?? '—'}</strong>
          </div>
          <div>
            <div className="stat-label">ABAC Role</div>
            <span className={`badge ${isPrivilegeHigh ? 'badge-admin' : 'badge-user'}`}>
              {(policy?.user?.relevantRoles ?? ['guest']).join(', ')}
            </span>
          </div>
          <div>
            <div className="stat-label">All Roles</div>
            <div>{userRoles.length > 0
              ? userRoles.map(r => <span key={r} className={`badge ${r === 'admin' ? 'badge-admin' : r === 'user' ? 'badge-user' : 'badge-none'}`} style={{ marginRight: '0.25rem' }}>{r}</span>)
              : <span className="badge badge-none">none</span>}
            </div>
          </div>
          <div>
            <div className="stat-label">Rules Match</div>
            <strong>{matchCount}/{totalRules}</strong>
          </div>
          <div>
            <div className="stat-label">Default</div>
            <span className={`badge ${policy?.default_action === 'deny' ? 'badge-deny' : 'badge-allow'}`}>
              {policy?.default_action ?? 'allow'}
            </span>
          </div>
        </div>
      </div>

      {rawToken && jwtPayload && (
        <div className="card">
          <h2>JWT Token</h2>

          {/* Raw token toggle */}
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <span className="stat-label">Raw Token</span>
              <button
                className="btn btn-secondary"
                style={{ padding: '0.125rem 0.5rem', fontSize: '0.7rem' }}
                onClick={() => setShowRawToken(v => !v)}
              >
                {showRawToken ? 'Hide' : 'Show'}
              </button>
            </div>
            {showRawToken && (
              <code className="mono" style={{
                display: 'block', wordBreak: 'break-all', padding: '0.5rem',
                background: '#f9fafb', borderRadius: '4px', fontSize: '0.7rem',
                lineHeight: '1.4', maxHeight: '80px', overflowY: 'auto',
                border: '1px solid #e5e7eb',
              }}>
                {rawToken}
              </code>
            )}
          </div>

          {/* ABAC-relevant fields highlighted */}
          <div className="stat-label" style={{ marginBottom: '0.5rem' }}>ABAC-Relevant Claims</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '1rem' }}>
            {/* Roles */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>realm_access.roles</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                {((jwtPayload.realm_access as any)?.roles ?? []).map((r: string) => (
                  <span key={r} className={`badge ${r === 'admin' ? 'badge-admin' : r === 'user' ? 'badge-user' : r === 'protected-reader' ? 'badge-allow' : 'badge-none'}`}>
                    {r}
                  </span>
                ))}
                {((jwtPayload.realm_access as any)?.roles ?? []).length === 0 && <span className="badge badge-none">none</span>}
              </div>
            </div>
            {/* Scope */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>scope</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                {String(jwtPayload.scope ?? '').split(' ').filter(Boolean).map(s => (
                  <span key={s} className={`badge ${s === 'api_protected:read' ? 'badge-allow' : 'badge-none'}`}>
                    {s}
                  </span>
                ))}
              </div>
            </div>
            {/* Email */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>email</span>
              <code className="cond-val">{String(jwtPayload.email ?? '—')}</code>
              {jwtPayload.email_verified
                ? <span className="badge badge-allow">verified</span>
                : <span className="badge badge-deny">not verified</span>}
            </div>
            {/* Sub */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>sub</span>
              <code className="cond-val mono" style={{ fontSize: '0.7rem' }}>{String(jwtPayload.sub ?? '—')}</code>
            </div>
            {/* Issuer */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>iss</span>
              <code className="cond-val mono" style={{ fontSize: '0.7rem' }}>{String(jwtPayload.iss ?? '—')}</code>
            </div>
            {/* Audience */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>aud</span>
              <code className="cond-val">{Array.isArray(jwtPayload.aud) ? jwtPayload.aud.join(', ') : String(jwtPayload.aud ?? '—')}</code>
            </div>
            {/* Expiry */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>exp</span>
              <code className="cond-val">{jwtPayload.exp ? new Date(jwtPayload.exp * 1000).toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh', hour12: false }) : '—'}</code>
            </div>
          </div>

          {/* Other claims */}
          <div className="stat-label" style={{ marginBottom: '0.25rem' }}>Other Claims</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
            {Object.entries(jwtPayload).filter(([k]) => !['exp', 'iat', 'jti', 'azp', 'typ', 'sid', 'acr', 'allowed-origins', 'realm_access', 'resource_access', 'scope', 'clientId', 'clientHost', 'clientAddress', 'email_verified', 'preferred_username', 'iss', 'aud', 'sub', 'email'].includes(k)).map(([key, value]) => {
              const display = typeof value === 'object' ? JSON.stringify(value) : String(value);
              return (
                <span key={key} className="badge badge-none" style={{ textTransform: 'none', letterSpacing: 'normal' }}>
                  <strong>{key}:</strong> {display.length > 40 ? display.slice(0, 40) + '...' : display}
                </span>
              );
            })}
          </div>
        </div>
      )}

      <div className="card">
        <h2>Current ABAC Context</h2>
        <p className="hint">Environment attributes evaluated at request time — timezone: <strong>Asia/Ho_Chi_Minh (UTC+7)</strong></p>
        <div className="context-grid">
          <div className="context-item">
            <span className="stat-label">Request Time</span>
            <strong>{ctx.timeStr}</strong>
          </div>
          <div className="context-item">
            <span className="stat-label">Hour</span>
            <strong>{ctx.hour}h</strong>
          </div>
          <div className="context-item">
            <span className="stat-label">Day of Week</span>
            <strong>{ctx.dayName} ({ctx.dayOfWeek})</strong>
            {ctx.isWeekend && <span className="badge badge-deny" style={{ marginLeft: '0.5rem' }}>WEEKEND</span>}
          </div>
          <div className="context-item">
            <span className="stat-label">Business Hours</span>
            {ctx.hour >= 7 && ctx.hour <= 22
              ? <span className="badge badge-allow">Yes (7:00–22:00)</span>
              : <span className="badge badge-deny">No (outside 7:00–22:00)</span>}
          </div>
          <div className="context-item">
            <span className="stat-label">Email</span>
            {policy?.user?.email
              ? <span className="badge badge-allow">{policy.user.email}{policy?.user?.emailVerified ? ' (verified)' : ''}</span>
              : <span className="badge badge-deny">No email</span>}
          </div>
          <div className="context-item">
            <span className="stat-label">Client Cert</span>
            <span className="badge badge-deny">Not presented</span>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>ABAC Policy Rules ({totalRules})</h2>
        <p className="hint">
          Each rule evaluates <strong>attributes</strong> (roles, time, client cert, email, etc.).{' '}
          {policy?.default_action === 'deny'
            ? <span>Default <strong>deny</strong> — only explicitly allowed requests pass.</span>
            : <span>Default <strong>allow</strong> — only explicitly denied requests are blocked.</span>}
        </p>
        <div className="table-wrap">
          <table className="abac-table rules-table">
            <thead>
              <tr>
                <th style={{ width: '140px' }}>Rule</th>
                <th style={{ width: '140px' }}>Path</th>
                <th>Attribute Conditions</th>
                <th style={{ width: '70px' }}>Action</th>
                <th style={{ width: '90px' }}>Match</th>
              </tr>
            </thead>
            <tbody>
              {policy?.rules?.map((rule) => {
                const details = rule.conditionDetails ?? [];
                const isRowMatch = rule.userMatch;
                return (
                  <tr key={rule.name} className={isRowMatch ? 'row-match' : 'row-no-match'}>
                    <td><strong>{rule.name}</strong></td>
                    <td className="mono">
                      {rule.match.path_prefix
                        ? <><span className="tag">prefix</span> {rule.match.path_prefix}</>
                        : rule.match.path
                          ? <><span className="tag">exact</span> {rule.match.path}</>
                          : <span className="dim">—</span>}
                    </td>
                    <td>
                      {details.length > 0 ? (
                        <div className="cond-list">
                          {details.map((d, i) => (
                            <div key={i} className={`cond-row ${d.result ? 'cond-pass' : 'cond-fail'}`}>
                              <div className="cond-req">
                                <span className="cond-label">Required: </span>
                                <span className="cond-text">{friendlyFact(d.fact)}</span>
                                <span className="cond-op">{friendlyOperator(d.operator)}</span>
                                <code className="cond-val">{formatExpected(d.fact, d.operator, d.expected)}</code>
                              </div>
                              <div className="cond-act">
                                <span className="cond-label">Your value: </span>
                                <code className="cond-val">{formatActual(d.fact, d.actual)}</code>
                                <span className={`cond-result ${d.result ? 'cond-result-pass' : 'cond-result-fail'}`}>
                                  {d.result ? '✓' : '✗'}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : rule.action === 'deny' ? (
                        <span className="dim">Always blocked</span>
                      ) : (
                        <span className="badge badge-allow" style={{ fontSize: '0.7rem' }}>No conditions</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${rule.action === 'deny' ? 'badge-deny' : 'badge-allow'}`}>
                        {rule.action}
                      </span>
                    </td>
                    <td>
                      {rule.action === 'deny'
                        ? <span className="badge badge-deny">BLOCKED</span>
                        : isRowMatch
                          ? <span className="badge badge-allow">MATCH</span>
                          : <span className="badge badge-deny">MISMATCH</span>}
                    </td>
                  </tr>
                );
              })}
              {(!policy?.rules || policy.rules.length === 0) && (
                <tr><td colSpan={5} className="dim text-center">No rules loaded</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
