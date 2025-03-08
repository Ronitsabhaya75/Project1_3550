"""
HTTP server for handling authentication and JWKS endpoints.
Supports RSA key generation, JWT signing, and proper HTTP method enforcement.
Uses SQLite for storing private keys.
"""

import http.server
import json
import socketserver
import time
import uuid
import sqlite3
from urllib.parse import urlparse, parse_qs
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"

class JWKSManager:
    """Manages JSON Web Key Sets (JWKS) with SQLite backend."""

    def __init__(self):
        """Initializes JWKSManager and sets up the SQLite database."""
        self.conn = sqlite3.connect(DB_FILE)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        """Creates the keys table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        self.conn.commit()

    def generate_key(self):
        """
        Generates a new RSA private/public key pair.
        
        Returns:
            private_pem (bytes): The private key in PEM format.
            public_pem (bytes): The public key in PEM format.
            private_key (RSAPrivateKey): The private key object for signing JWTs.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem, private_key

    def generate_keys(self, expiry: int):
        """
        Generates a new RSA key pair and stores it in the database with an expiration time.
        
        Args:
            expiry (int): The expiry time for the key in Unix timestamp format.

        Returns:
            key_id (int): The key ID associated with the newly generated keys.
        """
        private_pem, public_pem, private_key = self.generate_key()
        self.cursor.execute("""
            INSERT INTO keys (key, exp) VALUES (?, ?)
        """, (private_pem, expiry))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_key(self, kid: int):
        """
        Retrieves a private key from the database by its key ID.
        
        Args:
            kid (int): The key ID to retrieve.

        Returns:
            dict: The key data including the private key and expiry time.
        """
        self.cursor.execute("""
            SELECT key, exp FROM keys WHERE kid = ?
        """, (kid,))
        row = self.cursor.fetchone()
        if row:
            return {
                "private": row[0],
                "expiry": row[1],
                "private_key_obj": serialization.load_pem_private_key(row[0], password=None)
            }
        return None

    def get_valid_keys(self):
        """
        Retrieves all valid (non-expired) keys from the database.
        
        Returns:
            list: A list of valid keys.
        """
        current_time = time.time()
        self.cursor.execute("""
            SELECT kid, key, exp FROM keys WHERE exp > ?
        """, (current_time,))
        return self.cursor.fetchall()

jwks_manager = JWKSManager()

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handles HTTP requests for authentication and JWKS endpoints."""
    
    def _handle_valid_paths(self):
        """
        Validates whether the requested path is allowed (either '/auth' or '/.well-known/jwks.json').

        Returns:
            bool: True if the request path is valid, False otherwise.
        """
        valid_paths = ["/auth", "/.well-known/jwks.json"]
        return self.path.split('?')[0] in valid_paths

    def _send_method_not_allowed(self, allowed_methods):
        """
        Sends a 405 Method Not Allowed response along with the allowed HTTP methods.
        
        Args:
            allowed_methods (list): A list of allowed HTTP methods for the current request path.
        """
        self.send_response(405)
        self.send_header("Allow", ", ".join(allowed_methods))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(
            {"error": f"{self.command} method not allowed"}
        ).encode("utf-8"))

    def do_GET(self):
        """
        Handles GET requests for the '/.well-known/jwks.json' endpoint.
        
        Responds with the current JWKS containing public keys and their associated metadata
        if they are still valid based on the current time.
        """
        if self.path.startswith("/.well-known/jwks.json"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            valid_keys = []
            current_time = time.time()

            # Loop through stored keys and filter out expired ones
            for kid, key_data, exp in jwks_manager.get_valid_keys():
                try:
                    # Load the private key from the PEM format
                    private_key = serialization.load_pem_private_key(key_data, password=None)
                    
                    # Extract the public key from the private key
                    public_key = private_key.public_key()
                    numbers = public_key.public_numbers()

                    # Add the public key to the JWKS
                    valid_keys.append({
                        "kid": str(kid),
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "n": jwt.utils.base64url_encode(
                            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                        ).decode('utf-8'),
                        "e": jwt.utils.base64url_encode(
                            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                        ).decode('utf-8')
                    })
                except Exception as e:
                    print(f"Error processing key {kid}: {e}")
                    continue

            # Send the JWKS response
            response = {"keys": valid_keys}
            self.wfile.write(json.dumps(response).encode("utf-8"))
        elif self.path.startswith("/auth"):
            self._send_method_not_allowed(["POST"])
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        if self.path.startswith("/auth"):
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            expired = query_params.get('expired', [''])[0].lower() == 'true'
            
            current_time = time.time()
            if expired:
                # Generate an expired key
                expiry_time = int(current_time - 10)  # 10 seconds in the past
                selected_kid = jwks_manager.generate_keys(expiry=expiry_time)
            else:
                # Generate a valid key
                expiry_time = int(current_time + 600)  # 10 minutes in the future
                valid_kids = [
                    kid for kid, key, exp in jwks_manager.get_valid_keys()
                    if exp > current_time  # Ensure the key is not expired
                ]
                if valid_kids:
                    # Use an existing valid key
                    selected_kid = valid_kids[0]
                else:
                    # Generate a new valid key
                    selected_kid = jwks_manager.generate_keys(expiry=expiry_time)

            # Retrieve the key data
            key_data = jwks_manager.get_key(selected_kid)
            if not key_data:
                self.send_error(500, "Internal Server Error: Key not found")
                return

            # Create the JWT
            try:
                token = jwt.encode(
                    {"sub": "mock-user", "exp": expiry_time},
                    key_data["private_key_obj"],
                    algorithm="RS256",
                    headers={"kid": str(selected_kid), "typ": "JWT"}
                )
            except Exception as e:
                self.send_error(500, f"Internal Server Error: Failed to encode JWT - {e}")
                return

            # Send the response
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode("utf-8"))

    def do_PATCH(self):
        """Handle PATCH requests properly with full HTTP compliance"""
        if self._handle_valid_paths():
            # 1. Read request body (if any) to prevent timeout
            content_length = 0
            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                pass  # Handle invalid Content-Length
            
            if content_length > 0:
                self.rfile.read(content_length)  # Consume body

            # 2. Send proper response with Allow header
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.send_header("Allow", "POST" if self.path.startswith("/auth") else "GET, HEAD")
            self.send_header("Connection", "close")  # Force connection closure
            self.end_headers()
            
            # 3. Send error payload
            response_data = {
                "error": "Method Not Allowed",
                "message": "PATCH is not supported for this resource"
            }
            self.wfile.write(json.dumps(response_data).encode())
            self.close_connection = True  # Critical for preventing timeout
        else:
            self.send_error(404, "Not Found")

    def do_HEAD(self):
        """
        Handles HEAD requests for the '/.well-known/jwks.json' endpoint.
        
        Responds with status 200 and the appropriate headers without sending the body.
        """
        if self.path.startswith("/.well-known/jwks.json"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        elif self.path.startswith("/auth"):
            self._send_method_not_allowed(["POST"])
        else:
            self.send_error(404, "Not Found")

def run_server():
    """
    Starts the HTTP server on the specified port (8080).
    
    The server will handle incoming requests using the SimpleHTTPRequestHandler.
    """
    with socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler) as httpd:
        print(f"Serving on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()