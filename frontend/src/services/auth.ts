import api from './api';

interface AuthResponse {
  access_token?: string;
  token?: string;
  jwt?: string;
  message?: string;
}

export async function login(
  username: string,
  password: string,
): Promise<AuthResponse> {
  const data = await api.post<AuthResponse>('/api/auth/login', {
    username,
    password,
  });
  const token = data.access_token ?? data.token ?? data.jwt;
  if (token) {
    sessionStorage.setItem('jwt', token);
  }
  return data;
}

export async function register(
  username: string,
  password: string,
  email: string,
): Promise<AuthResponse> {
  return api.post<AuthResponse>('/api/auth/register', {
    username,
    password,
    email,
  });
}

export function logout(): void {
  sessionStorage.removeItem('jwt');
  window.location.href = '/login';
}

export function getToken(): string | null {
  return sessionStorage.getItem('jwt');
}

export function isAuthenticated(): boolean {
  return sessionStorage.getItem('jwt') !== null;
}
