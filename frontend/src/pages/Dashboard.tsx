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
  const [responses, setResponses] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
      return;
    }
    const token = getToken();
    if (token) setPayload(decodeJwt(token));
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
    { name: 'Admin Data', path: '/api/admin-data' },
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

      <div className="card">
        <h2>JWT Payload</h2>
        <pre className="response-area jwt-payload">
          {payload ? JSON.stringify(payload, null, 2) : 'Not available'}
        </pre>
      </div>

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
