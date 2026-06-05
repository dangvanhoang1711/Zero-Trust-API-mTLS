import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
    KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "zero-trust")
    KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "api-gateway")
    KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")
    OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")
    JWT_ISSUER = os.environ.get("JWT_ISSUER", "")
    JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "")
    OIDC_DISCOVERY_CACHE_TTL = int(os.environ.get("OIDC_DISCOVERY_CACHE_TTL", "300"))
    JWKS_CACHE_TTL = int(os.environ.get("JWKS_CACHE_TTL", "300"))
