import unittest
import requests
import sqlite3
import time
import jwt
from cryptography.hazmat.primitives import serialization

BASE_URL = "http://127.0.0.1:8080"
DB_FILE = "totally_not_my_privateKeys.db"

class TestAuthServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Ensure the server is running before running tests."""
        cls.session = requests.Session()

    def test_1_valid_jwt(self):
        """Test requesting a valid JWT."""
        response = self._request_jwt(expired=False)
        self.assertEqual(response.status_code, 200)
        token = response.json().get("token")
        self.assertIsNotNone(token)
        self._validate_jwt(token, should_be_expired=False)

    def test_2_expired_jwt(self):
        """Test requesting an expired JWT."""
        response = self._request_jwt(expired=True)
        self.assertEqual(response.status_code, 200)
        token = response.json().get("token")
        self.assertIsNotNone(token)
        self._validate_jwt(token, should_be_expired=True)

    def test_3_database_has_keys(self):
        """Test that the database contains at least one key."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        self.assertGreater(count, 0, "Database should contain at least one key.")
        conn.close()

    def test_4_database_valid_and_expired_keys(self):
        """Test that the database contains both valid and expired keys."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        now = int(time.time())
        cursor.execute("SELECT exp FROM keys")
        rows = cursor.fetchall()
        valid_keys = 0
        expired_keys = 0

        for row in rows:
            exp = row[0]
            if exp > now:
                valid_keys += 1
            else:
                expired_keys += 1

        self.assertGreater(valid_keys, 0, "Database should contain at least one valid key.")
        self.assertGreater(expired_keys, 0, "Database should contain at least one expired key.")
        conn.close()

    def test_5_jwks_endpoint_returns_keys(self):
        """Test that the JWKS endpoint returns valid keys."""
        response = self.session.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        self.assertGreater(len(jwks["keys"]), 0, "JWKS should contain at least one key.")

    def test_6_jwks_endpoint_returns_valid_keys(self):
        """Test that the JWKS endpoint returns keys with valid structure."""
        response = self.session.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        for key in jwks["keys"]:
            self.assertIn("kid", key)
            self.assertIn("kty", key)
            self.assertIn("use", key)
            self.assertIn("alg", key)
            self.assertIn("n", key)
            self.assertIn("e", key)

    def test_7_invalid_path_returns_404(self):
        """Test that an invalid path returns a 404 error."""
        response = self.session.get(f"{BASE_URL}/invalid-path")
        self.assertEqual(response.status_code, 404)

    def test_8_auth_endpoint_rejects_get_requests(self):
        """Test that the /auth endpoint rejects GET requests."""
        response = self.session.get(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 405)

    def test_9_jwt_contains_correct_claims(self):
        """Test that the JWT contains the correct claims."""
        response = self._request_jwt(expired=False)
        self.assertEqual(response.status_code, 200)
        token = response.json().get("token")
        self.assertIsNotNone(token)

        # Decode the token without verification to inspect its claims
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn("sub", decoded)
        self.assertEqual(decoded["sub"], "mock-user")
        self.assertIn("exp", decoded)

    def _request_jwt(self, expired=False):
        """Helper function to request a JWT."""
        url = f"{BASE_URL}/auth"
        if expired:
            url += "?expired=true"
        return self.session.post(url)

    def _validate_jwt(self, token, should_be_expired=False):
        """Helper function to validate a JWT."""
        try:
            # Decode the token without verification to inspect its claims
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get("exp")
            self.assertIsNotNone(exp, "JWT does not contain an expiration claim.")

            # Check if the token is expired
            now = int(time.time())
            if should_be_expired:
                self.assertLess(exp, now, "JWT should be expired but is not.")
            else:
                self.assertGreater(exp, now, "JWT should be valid but is expired.")
        except jwt.PyJWTError as e:
            self.fail(f"JWT validation failed: {e}")

if __name__ == "__main__":
    unittest.main()