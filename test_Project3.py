import unittest
import requests
import json
import time
import sqlite3
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

BASE_URL = "http://127.0.0.1:8080"
DB_FILE = "totally_not_my_privateKeys.db"

class TestJWKSServer(unittest.TestCase):

    def test_1_jwks_endpoint_availability(self):
        """Test JWKS endpoint returns valid keys"""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0)
        
        key = data["keys"][0]
        for field in ["kty", "use", "alg", "n", "e"]:
            self.assertIn(field, key)

    def test_2_valid_authentication(self):
        """Test successful authentication"""
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        
        token = response.json().get("token")
        self.assertIsNotNone(token)
        
        # Verify token structure
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["typ"], "JWT")
        self.assertIn("kid", header)
        
        # Check auth was logged
        self.assertTrue(self._check_auth_logged(response))


    def test_3_user_registration(self):
        """Test user registration flow"""
        test_user = {
            "username": f"testuser_{int(time.time())}",
            "email": f"test_{int(time.time())}@example.com"
        }
        
        response = requests.post(
            f"{BASE_URL}/register",
            json=test_user
        )
        self.assertEqual(response.status_code, 201)
        
        data = response.json()
        self.assertIn("password", data)
        self.assertGreater(len(data["password"]), 10)
        
        # Verify user exists in DB
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (test_user["username"],))
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(result)
        self.assertNotEqual(result[0], data["password"])  # Password should be hashed

    def test_4_rate_limiting(self):
        """Test rate limiting functionality"""
        # First make sure we're not rate limited from previous tests
        time.sleep(1)
        
        # Send requests up to the limit
        for i in range(10):
            response = requests.post(f"{BASE_URL}/auth")
            self.assertEqual(response.status_code, 200)
        
        # Next request should be rate limited
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 429)
        
        # Wait for window to reset
        time.sleep(1.1)
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)

    def test_5_key_encryption(self):
        """Verify keys are encrypted in database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM keys LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(result)
        key_data = result[0]
        self.assertTrue(key_data.startswith(b'enc:'))


    def test_6_auth_logging(self):
        """Verify authentication attempts are logged"""
        # Make test request
        test_ip = "127.0.0.1"
        response = requests.post(f"{BASE_URL}/auth")
        
        # Check logs in database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM auth_logs WHERE request_ip = ? AND status_code = 200",
            (test_ip,)
        )
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertGreater(count, 0)

    def test_7_jwt_verification(self):
        """Verify generated JWTs can be properly verified"""
        # Get current JWKS
        jwks_response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        jwks_data = jwks_response.json()
        
        # Get a new token
        token_response = requests.post(f"{BASE_URL}/auth")
        token = token_response.json()["token"]
        
        # Get the key for verification
        header = jwt.get_unverified_header(token)
        kid = header["kid"]
        
        # Find the matching key in JWKS
        key_data = next(k for k in jwks_data["keys"] if k["kid"] == kid)
        
        # Reconstruct public key
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        
        # Verify token
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_exp": False}
        )
        
        self.assertEqual(decoded["sub"], "mock-user")

    def _check_auth_logged(self, response):
        """Helper to check if auth was logged"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM auth_logs WHERE request_ip = ? AND status_code = ?",
            ("127.0.0.1", response.status_code)
        )
        result = cursor.fetchone()
        conn.close()
        return result is not None

if __name__ == "__main__":
    unittest.main()