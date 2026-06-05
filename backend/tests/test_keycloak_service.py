import unittest

from app import create_app
from services.keycloak import KeycloakService


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ValueError(f"http {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, get_responses=None, post_response=None):
        self._get_responses = get_responses or {}
        self._post_response = post_response or FakeResponse({})
        self.get_calls = []
        self.post_calls = []

    def get(self, url, timeout=10, **kwargs):
        self.get_calls.append((url, timeout, kwargs))
        return self._get_responses[url]

    def post(self, url, data=None, json=None, headers=None, timeout=10, **kwargs):
        self.post_calls.append(
            {
                "url": url,
                "data": data,
                "json": json,
                "headers": headers,
                "timeout": timeout,
                "kwargs": kwargs,
            }
        )
        return self._post_response


class KeycloakServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_get_token_uses_discovery_endpoint_and_omits_empty_client_secret(self):
        discovery_url = "http://keycloak:8080/realms/zero-trust/.well-known/openid-configuration"
        token_endpoint = "http://keycloak:8080/realms/zero-trust/protocol/openid-connect/token"

        service = KeycloakService()
        service._session = FakeSession(
            get_responses={
                discovery_url: FakeResponse({"token_endpoint": token_endpoint}),
            },
            post_response=FakeResponse({"access_token": "token-value"}),
        )

        response = service.get_token("alice", "secret")

        self.assertEqual(response["access_token"], "token-value")
        self.assertEqual(len(service._session.get_calls), 1)
        self.assertEqual(len(service._session.post_calls), 1)
        self.assertEqual(service._session.post_calls[0]["url"], token_endpoint)
        self.assertEqual(
            service._session.post_calls[0]["data"],
            {
                "client_id": "api-gateway",
                "username": "alice",
                "password": "secret",
                "grant_type": "password",
            },
        )
