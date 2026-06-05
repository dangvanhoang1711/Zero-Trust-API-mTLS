import unittest
from unittest.mock import patch

from app import create_app
from routes import api as api_routes


class AppRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_public_api_endpoint(self):
        response = self.client.get("/api/public")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"message": "public"})

    def test_profile_requires_bearer_token(self):
        response = self.client.get("/api/profile")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "Missing authorization token")

    def test_user_data_allows_user_role(self):
        with patch.object(
            api_routes.validator,
            "verify_token",
            return_value={"sub": "alice", "realm_access": {"roles": ["user"]}},
        ):
            response = self.client.get(
                "/api/user-data",
                headers={"Authorization": "Bearer valid-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "User data")

    def test_admin_data_rejects_non_admin_role(self):
        with patch.object(
            api_routes.validator,
            "verify_token",
            return_value={"sub": "alice", "realm_access": {"roles": ["user"]}},
        ):
            response = self.client.get(
                "/api/admin-data",
                headers={"Authorization": "Bearer valid-token"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "Insufficient privileges")
