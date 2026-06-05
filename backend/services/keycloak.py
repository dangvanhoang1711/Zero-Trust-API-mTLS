import time

import requests

from flask import current_app


class KeycloakService:
    def __init__(self):
        self._session = requests.Session()
        self._base_url = None
        self._realm = None
        self._client_id = None
        self._client_secret = None
        self._oidc_config_cache = None
        self._oidc_config_fetched_at = 0.0

    def _init_from_app(self):
        cfg = current_app.config
        self._base_url = cfg["KEYCLOAK_URL"].rstrip("/")
        self._realm = cfg["KEYCLOAK_REALM"]
        self._client_id = cfg["KEYCLOAK_CLIENT_ID"]
        self._client_secret = cfg["KEYCLOAK_CLIENT_SECRET"]

    def _cache_ttl(self):
        return current_app.config.get("OIDC_DISCOVERY_CACHE_TTL", 300)

    def _oidc_discovery_url(self):
        configured = current_app.config.get("OIDC_DISCOVERY_URL", "").strip()
        if configured:
            return configured
        return f"{self._base_url}/realms/{self._realm}/.well-known/openid-configuration"

    def _oidc_config(self):
        now = time.time()
        if self._oidc_config_cache and (now - self._oidc_config_fetched_at) < self._cache_ttl():
            return self._oidc_config_cache

        resp = self._session.get(self._oidc_discovery_url(), timeout=10)
        resp.raise_for_status()
        self._oidc_config_cache = resp.json()
        self._oidc_config_fetched_at = now
        return self._oidc_config_cache

    def _token_url(self):
        return self._oidc_config().get(
            "token_endpoint",
            f"{self._base_url}/realms/{self._realm}/protocol/openid-connect/token",
        )

    def _admin_url(self):
        return f"{self._base_url}/admin/realms/{self._realm}"

    def _client_auth_payload(self):
        payload = {
            "client_id": self._client_id,
        }
        if self._client_secret:
            payload["client_secret"] = self._client_secret
        return payload

    def get_token(self, username, password):
        self._init_from_app()
        payload = {
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        payload.update(self._client_auth_payload())
        resp = self._session.post(self._token_url(), data=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def create_user(self, username, password, email):
        self._init_from_app()
        admin_token = self._get_admin_token()
        headers = {"Authorization": f"Bearer {admin_token}"}
        payload = {
            "username": username,
            "email": email,
            "enabled": True,
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        }
        resp = self._session.post(
            f"{self._admin_url()}/users",
            json=payload,
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.status_code == 201

    def get_realm_roles(self):
        self._init_from_app()
        admin_token = self._get_admin_token()
        headers = {"Authorization": f"Bearer {admin_token}"}
        resp = self._session.get(
            f"{self._admin_url()}/roles",
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def assign_role(self, user_id, role_name):
        self._init_from_app()
        admin_token = self._get_admin_token()
        headers = {"Authorization": f"Bearer {admin_token}"}
        roles_resp = self._session.get(
            f"{self._admin_url()}/roles",
            headers=headers,
            timeout=10,
        )
        roles_resp.raise_for_status()
        role = next(
            (r for r in roles_resp.json() if r["name"] == role_name), None
        )
        if not role:
            raise ValueError(f"Role '{role_name}' not found")
        payload = [{"id": role["id"], "name": role["name"]}]
        resp = self._session.post(
            f"{self._admin_url()}/users/{user_id}/role-mappings/realm",
            json=payload,
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.status_code == 204

    def _get_admin_token(self):
        payload = {
            "grant_type": "client_credentials",
        }
        payload.update(self._client_auth_payload())
        resp = self._session.post(self._token_url(), data=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()["access_token"]
