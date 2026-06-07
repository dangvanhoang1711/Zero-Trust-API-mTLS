import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getToken, logout, isAuthenticated } from '../services/auth';
import api from '../services/api';

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
  roles?: string[];
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

export default function Dashboard() {
  const navigate = useNavigate();
  const [payload, setPayload] = useState<JwtPayload | null>(null);
  const [rawToken, setRawToken] = useState<string>('');
  const [showRawToken, setShowRawToken] = useState(false);
  const [responses, setResponses] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
      return;
    }
    const token = getToken();
    if (token) {
      setRawToken(token);
      setPayload(decodeJwt(token));
    }
  }, [navigate]);

  const callEndpoint = useCallback(async (name: string, endpoint: string) => {
    setLoading((prev) => ({ ...prev, [name]: true }));
    try {
      const data = await api.get<unknown>(endpoint);
      setResponses((prev) => ({
        ...prev,
        [name]: JSON.stringify(data, null, 2),
      }));
    } catch (err) {
      setResponses((prev) => ({
        ...prev,
        [name]: `Error: ${err instanceof Error ? err.message : 'Request failed'}`,
      }));
    } finally {
      setLoading((prev) => ({ ...prev, [name]: false }));
    }
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const endpoints: { name: string; path: string }[] = [
    { name: 'Public', path: '/api/public' },
    { name: 'Profile', path: '/api/profile' },
    { name: 'User Data', path: '/api/user-data' },
    { name: 'Director Data', path: '/api/director-data' },
    { name: 'JWT Info', path: '/api/jwt-info' },
  ];

  return (
    <>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2>Dashboard</h2>
          <button className="btn btn-danger" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </div>

      {payload && (
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
                {(payload.realm_access?.roles ?? []).map(r => (
                  <span key={r} className={`badge ${r === 'director' ? 'badge-admin' : r === 'user' ? 'badge-user' : r === 'protected-reader' ? 'badge-allow' : 'badge-none'}`}>
                    {r}
                  </span>
                ))}
                {(payload.realm_access?.roles ?? []).length === 0 && <span className="badge badge-none">none</span>}
              </div>
            </div>
            {/* Scope */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>scope</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                {String(payload.scope ?? '').split(' ').filter(Boolean).map(s => (
                  <span key={s} className={`badge ${s === 'api_protected:read' ? 'badge-allow' : 'badge-none'}`}>
                    {s}
                  </span>
                ))}
              </div>
            </div>
            {/* Email */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>email</span>
              <code className="cond-val">{String(payload.email ?? '—')}</code>
              {payload.email_verified
                ? <span className="badge badge-allow">verified</span>
                : <span className="badge badge-deny">not verified</span>}
            </div>
            {/* Sub */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>sub</span>
              <code className="cond-val mono" style={{ fontSize: '0.7rem' }}>{String(payload.sub ?? '—')}</code>
            </div>
            {/* Issuer */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>iss</span>
              <code className="cond-val mono" style={{ fontSize: '0.7rem' }}>{String(payload.iss ?? '—')}</code>
            </div>
            {/* Expiry */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ minWidth: '140px', color: '#6b7280', fontStyle: 'italic' }}>exp</span>
              <code className="cond-val">{payload.exp ? new Date(payload.exp * 1000).toLocaleTimeString('en-US', { hour12: false }) : '—'}</code>
            </div>
          </div>

          {/* Full decoded payload */}
          <div className="stat-label" style={{ marginBottom: '0.25rem' }}>Full Decoded Payload</div>
          <pre className="response-area jwt-payload" style={{ fontSize: '0.75rem', maxHeight: '200px', overflowY: 'auto' }}>
            {JSON.stringify(payload, null, 2)}
          </pre>
        </div>
      )}

      <div className="card">
        <h2>API Endpoints</h2>
        <div className="endpoint-buttons">
          {endpoints.map((ep) => (
            <button
              key={ep.name}
              className="btn btn-secondary"
              onClick={() => callEndpoint(ep.name, ep.path)}
              disabled={loading[ep.name]}
            >
              {loading[ep.name] ? 'Loading...' : `GET ${ep.name}`}
            </button>
          ))}
        </div>
        {Object.entries(responses).map(([name, data]) => (
          <div key={name} style={{ marginBottom: '0.75rem' }}>
            <strong style={{ fontSize: '0.875rem' }}>{name}</strong>
            <div className="response-area">{data}</div>
          </div>
        ))}
      </div>
    </>
  );
}
