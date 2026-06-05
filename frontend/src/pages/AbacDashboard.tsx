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

interface PolicyRule {
  name: string;
  match: PolicyMatch;
  conditions: PolicyConditions;
  action: string;
  userMatch: boolean;
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
    preferred_username?: string;
    email?: string;
  };
}

interface EvalMatchingRule {
  name: string;
  action: string;
  conditionSatisfied: boolean;
}

interface EvalResponse {
  path: string;
  method: string;
  allowed: boolean;
  reason: string;
  matchingRules: EvalMatchingRule[];
  finalRule?: string;
  defaultAction: string;
}

interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  realm_access?: { roles: string[] };
  preferred_username?: string;
  email?: string;
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

const ALL_ENDPOINTS = [
  { name: 'Public', path: '/api/public', method: 'GET', icon: '🌐' },
  { name: 'Profile', path: '/api/profile', method: 'GET', icon: '👤' },
  { name: 'User Data', path: '/api/user-data', method: 'GET', icon: '📋' },
  { name: 'Admin Data', path: '/api/admin-data', method: 'GET', icon: '🔐' },
  { name: 'JWT Info', path: '/api/jwt-info', method: 'GET', icon: '🔑' },
  { name: 'Protected', path: '/protected', method: 'GET', icon: '🛡️' },
  { name: 'Admin (deny)', path: '/admin', method: 'GET', icon: '🚫' },
  { name: 'Secrets (deny)', path: '/secrets', method: 'GET', icon: '🗝️' },
];

export default function AbacDashboard() {
  const navigate = useNavigate();
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [rawToken, setRawToken] = useState<string | null>(null);
  const [evalResults, setEvalResults] = useState<Record<string, EvalResponse>>({});
  const [loadingEval, setLoadingEval] = useState<Record<string, boolean>>({});
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
      return;
    }
    const token = getToken();
    if (token) setRawToken(token);
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

  const testEndpoint = useCallback(async (name: string, path: string, method: string) => {
    setLoadingEval((prev) => ({ ...prev, [name]: true }));
    try {
      const data = await api.get<EvalResponse>(
        `/api/abac/evaluate?path=${encodeURIComponent(path)}&method=${encodeURIComponent(method)}`
      );
      setEvalResults((prev) => ({ ...prev, [name]: data }));
    } catch (err) {
      setEvalResults((prev) => ({
        ...prev,
        [name]: {
          path,
          method,
          allowed: false,
          reason: `Simulation error: ${err instanceof Error ? err.message : 'unknown'}`,
          matchingRules: [],
          defaultAction: 'deny',
        },
      }));
    } finally {
      setLoadingEval((prev) => ({ ...prev, [name]: false }));
    }
  }, []);

  const testAll = useCallback(async () => {
    for (const ep of ALL_ENDPOINTS) {
      await testEndpoint(ep.name, ep.path, ep.method);
    }
  }, [testEndpoint]);

  const jwtPayload = rawToken ? decodeJwt(rawToken) : null;
  const userRoles = policy?.user?.roles ?? jwtPayload?.realm_access?.roles ?? [];

  return (
    <>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2>ABAC Dashboard</h2>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-secondary" onClick={fetchPolicies}>Refresh</button>
            <button className="btn btn-danger" onClick={() => { logout(); navigate('/login'); }}>
              Logout
            </button>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      <div className="card">
        <h2>👤 User Information</h2>
        <table className="abac-table">
          <tbody>
            <tr><td className="label">Username</td><td>{policy?.user?.preferred_username ?? jwtPayload?.preferred_username ?? '—'}</td></tr>
            <tr><td className="label">Email</td><td>{policy?.user?.email ?? jwtPayload?.email ?? '—'}</td></tr>
            <tr><td className="label">Subject (sub)</td><td className="mono">{policy?.user?.sub ?? jwtPayload?.sub ?? '—'}</td></tr>
            <tr><td className="label">Issuer (iss)</td><td className="mono">{policy?.user?.iss ?? jwtPayload?.iss ?? '—'}</td></tr>
            <tr><td className="label">Audience (aud)</td><td className="mono">{JSON.stringify(policy?.user?.aud ?? jwtPayload?.aud ?? '—')}</td></tr>
            <tr><td className="label">Roles</td>
              <td>{userRoles.length > 0
                ? userRoles.map(r => <span key={r} className={`badge ${r === 'admin' ? 'badge-admin' : 'badge-user'}`}>{r}</span>)
                : <span className="badge badge-none">none</span>}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>📋 ABAC Policy Rules ({policy?.rules?.length ?? 0})</h2>
        <p className="hint">
          Default action: <strong>{policy?.default_action ?? 'allow'}</strong>
          &nbsp;—&nbsp;
          {policy?.default_action === 'deny'
            ? 'Only explicitly allowed requests pass'
            : 'Only explicitly denied requests are blocked'}
        </p>
        <div className="table-wrap">
          <table className="abac-table rules-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Match</th>
                <th>Conditions</th>
                <th>Action</th>
                <th>Your Access</th>
              </tr>
            </thead>
            <tbody>
              {policy?.rules?.map((rule) => (
                <tr key={rule.name} className={rule.userMatch ? 'row-match' : 'row-no-match'}>
                  <td><strong>{rule.name}</strong></td>
                  <td className="mono">
                    {rule.match.path_prefix
                      ? <><span className="tag">prefix</span> {rule.match.path_prefix}</>
                      : rule.match.path
                        ? <><span className="tag">exact</span> {rule.match.path}</>
                        : <span className="dim">—</span>}
                    {rule.match.methods && rule.match.methods.length > 0 && (
                      <div className="mt-025">
                        <span className="tag tag-method">{rule.match.methods.join(', ')}</span>
                      </div>
                    )}
                  </td>
                  <td className="mono">
                    {rule.conditions.constraint
                      ? <RenderConstraint constraint={rule.conditions.constraint as Record<string, unknown>} />
                      : rule.conditions.required_scopes?.length
                        ? `scopes: ${rule.conditions.required_scopes.join(', ')}`
                        : rule.conditions.token_subjects?.length
                          ? `sub in [${rule.conditions.token_subjects.join(', ')}]`
                          : rule.conditions.claims
                            ? `claims: ${Object.keys(rule.conditions.claims).join(', ')}`
                            : <span className="dim">none</span>}
                  </td>
                  <td>
                    <span className={`badge ${rule.action === 'deny' ? 'badge-deny' : 'badge-allow'}`}>
                      {rule.action}
                    </span>
                  </td>
                  <td>
                    {rule.userMatch
                      ? <span className="badge badge-allow">PASS</span>
                      : <span className="badge badge-deny">—</span>}
                  </td>
                </tr>
              ))}
              {(!policy?.rules || policy.rules.length === 0) && (
                <tr><td colSpan={5} className="dim text-center">No rules loaded</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2>🧪 Access Test Panel</h2>
          <button className="btn btn-primary" onClick={testAll}>Test All</button>
        </div>
        <p className="hint">Simulate ABAC evaluation for each endpoint (based on your JWT claims)</p>
        <div className="endpoint-buttons">
          {ALL_ENDPOINTS.map((ep) => (
            <button
              key={ep.name}
              className={`btn ${evalResults[ep.name]?.allowed === true ? 'btn-ok' : evalResults[ep.name]?.allowed === false ? 'btn-blocked' : 'btn-secondary'}`}
              onClick={() => testEndpoint(ep.name, ep.path, ep.method)}
              disabled={loadingEval[ep.name]}
            >
              {loadingEval[ep.name] ? '...' : `${ep.icon} ${ep.name}`}
            </button>
          ))}
        </div>
        {Object.entries(evalResults).map(([name, result]) => (
          <div key={name} className={`eval-result ${result.allowed ? 'eval-pass' : 'eval-deny'}`}>
            <div className="eval-header">
              <strong>{result.allowed ? '✅' : '❌'} {name}</strong>
              <span className={`badge ${result.allowed ? 'badge-allow' : 'badge-deny'}`}>
                {result.allowed ? 'ALLOWED' : 'DENIED'}
              </span>
            </div>
            <div className="eval-detail">{result.reason}</div>
            {result.finalRule && <div className="eval-detail">Matched rule: <strong>{result.finalRule}</strong></div>}
          </div>
        ))}
      </div>

      <div className="card">
        <h2>📊 Access Matrix: Roles × Endpoints</h2>
        <p className="hint">
          <span className="badge badge-allow">✓ Pass</span> = your roles satisfy the rule's conditions
          &nbsp;&nbsp;
          <span className="badge badge-deny">—</span> = your roles do NOT satisfy
        </p>
        <div className="table-wrap">
          <table className="abac-table matrix-table">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Action</th>
                <th>Required Role</th>
                <th>Your Role Match</th>
              </tr>
            </thead>
            <tbody>
              {[
                { ep: '/api/public', action: 'allow', role: 'any' },
                { ep: '/api/profile', action: 'allow', role: 'any (JWT required)' },
                { ep: '/api/user-data', action: 'allow', role: 'user' },
                { ep: '/api/admin-data', action: 'allow', role: 'admin' },
                { ep: '/api/jwt-info', action: 'allow', role: 'any (JWT required)' },
                { ep: '/protected', action: 'allow', role: 'any (JWT required)' },
                { ep: '/admin', action: 'deny', role: '—' },
                { ep: '/secrets', action: 'deny', role: '—' },
              ].map((row) => {
                const hasRole = row.role === 'any' || (row.role === 'any (JWT required)' && userRoles.length > 0) || userRoles.includes(row.role);
                return (
                  <tr key={row.ep}>
                    <td className="mono">{row.ep}</td>
                    <td>
                      <span className={`badge ${row.action === 'deny' ? 'badge-deny' : 'badge-allow'}`}>
                        {row.action}
                      </span>
                    </td>
                    <td>{row.role}</td>
                    <td>
                      {hasRole
                        ? <span className="badge badge-allow">✓ {userRoles.join(', ') || 'guest'}</span>
                        : <span className="badge badge-deny">✗ {userRoles.join(', ') || 'none'}</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

function RenderConstraint({ constraint }: { constraint: Record<string, unknown> }) {
  if (!constraint || typeof constraint !== 'object') return <span className="dim">—</span>;

  if ('all' in constraint) {
    const items = constraint['all'] as Record<string, unknown>[];
    return <div className="constraint-group">ALL [{items?.map((c, i) => <RenderConstraint key={i} constraint={c} />)}]</div>;
  }
  if ('any' in constraint) {
    const items = constraint['any'] as Record<string, unknown>[];
    return <div className="constraint-group">ANY [{items?.map((c, i) => <RenderConstraint key={i} constraint={c} />)}]</div>;
  }
  if ('not' in constraint) {
    const inner = constraint['not'] as Record<string, unknown>;
    return <div className="constraint-group">NOT <RenderConstraint constraint={inner} /></div>;
  }

  const fact = constraint['fact'] as string;
  const operator = constraint['operator'] as string;
  const value = constraint['value'];
  const valueStr = Array.isArray(value) ? `[${value.join(', ')}]` : String(value ?? '');

  return <span className="constraint-leaf">{fact} <strong>{operator}</strong> {valueStr}</span>;
}
