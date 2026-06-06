const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

async function parseResponseBody(res: Response): Promise<unknown> {
  if (res.status === 204) {
    return null;
  }

  const raw = await res.text();
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const token = sessionStorage.getItem('jwt');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (res.status === 401 && !endpoint.includes('/auth/')) {
    sessionStorage.removeItem('jwt');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  const data = await parseResponseBody(res);

  if (!res.ok) {
    if (typeof data === 'string' && data.trim()) {
      throw new Error(data);
    }

    if (isRecord(data)) {
      const error = data.error;
      const message = data.message;
      if (typeof error === 'string' && error.trim()) {
        throw new Error(error);
      }
      if (typeof message === 'string' && message.trim()) {
        throw new Error(message);
      }
    }

    throw new Error('Request failed');
  }

  return data as T;
}

function get<T>(endpoint: string): Promise<T> {
  return request<T>(endpoint, { method: 'GET' });
}

function post<T>(endpoint: string, body?: unknown): Promise<T> {
  return request<T>(endpoint, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

const api = { get, post };
export default api;
