"""
HTTP server for handling authentication and JWKS endpoints.
Supports RSA key generation, JWT signing, and proper HTTP method enforcement.
"""

import http.server
import json
import socketserver
import time
import uuid
from urllib.parse import urlparse, parse_qs
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PORT = 8080

class JWKSManager:
    """Manages JSON Web Key Sets (JWKS)."""

    def __init__(self):
        """Initializes JWKSManager, which will store RSA key pairs in a dictionary."""
        self.keys = {}

    def generate_key(self):
        """
        Generates a new RSA private/public key pair.
        
        This uses the cryptography library to create a private key, extracts the
        public key, and serializes both keys into PEM format.
        
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
        Generates a new RSA key pair and stores it in the JWKS with an expiration time.
        
        This method generates a key ID (kid) using UUID, stores the keys along
        with their expiration time, and returns the key ID.
        
        Args:
            expiry (int): The expiry time for the key in Unix timestamp format.

        Returns:
            key_id (str): The key ID associated with the newly generated keys.
        """
        key_id = str(uuid.uuid4())
        private_pem, public_pem, private_key = self.generate_key()
        self.keys[key_id] = {
            "private": private_pem,
            "public": public_pem,
            "expiry": expiry,
            "private_key_obj": private_key
        }
        return key_id

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
            for kid, key_data in jwks_manager.keys.items():
                if key_data["expiry"] > current_time:
                    pub_key = serialization.load_pem_public_key(key_data["public"])
                    numbers = pub_key.public_numbers()
                    valid_keys.append({
                        "kid": kid,
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

            self.wfile.write(json.dumps({"keys": valid_keys}).encode("utf-8"))
        elif self.path.startswith("/auth"):
            self._send_method_not_allowed(["POST"])
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """
        Handles POST requests for the '/auth' endpoint.
        
        Creates a JWT token based on the expiration parameter passed in the query string.
        If the 'expired' parameter is 'true', an expired token will be created.
        Otherwise, a valid token with a 10-minute expiration is generated.
        """
        if self.path.startswith("/auth"):
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            expired = query_params.get('expired', [''])[0].lower() == 'true'
            
            current_time = time.time()
            if expired:
                expiry_time = int(current_time - 10)
                selected_kid = jwks_manager.generate_keys(expiry=expiry_time)
            else:
                expiry_time = int(current_time + 600)
                valid_kids = [
                    kid for kid, key in jwks_manager.keys.items()
                    if key["expiry"] > expiry_time
                ]
                if valid_kids:
                    selected_kid = valid_kids[0]
                else:
                    selected_kid = jwks_manager.generate_keys(expiry=expiry_time)

            key_data = jwks_manager.keys[selected_kid]
            token = jwt.encode(
                {"sub": "mock-user", "exp": expiry_time},
                key_data["private_key_obj"],
                algorithm="RS256",
                headers={"kid": selected_kid}
            )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode("utf-8"))
        elif self.path == "/.well-known/jwks.json":
            self._send_method_not_allowed(["GET", "HEAD"])
        else:
            self.send_error(404, "Not Found")

    def do_PUT(self):
        """
        Handles PUT requests, ensuring that the correct methods are used for the '/auth' path.
        
        If an unsupported method is used (e.g., PUT on the '/auth' path), a 405 Method Not Allowed response
        is sent with the allowed methods.
        """
        if self._handle_valid_paths():
            if self.path.startswith("/auth"):
                self._send_method_not_allowed(["POST"])
            else:
                self._send_method_not_allowed(["GET", "HEAD"])
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self):
        """
        Handles DELETE requests, ensuring that the correct methods are used for the '/auth' path.
        
        Similar to the PUT request handling, this checks if the method is allowed and sends a 405 response
        with the allowed methods.
        """
        if self._handle_valid_paths():
            if self.path.startswith("/auth"):
                self._send_method_not_allowed(["POST"])
            else:
                self._send_method_not_allowed(["GET", "HEAD"])
        else:
            self.send_error(404, "Not Found")

    def do_PATCH(self):
        """
        Handles PATCH requests, sending a 405 Method Not Allowed response.
        
        This is necessary because PATCH is not a valid method for the defined paths.
        The response includes the allowed methods for that path.
        """
        if self._handle_valid_paths():
            self.send_response(405)
            self.send_header("Allow", "POST" if self.path.startswith("/auth") else "GET, HEAD")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            response_body = json.dumps({"error": "PATCH method not allowed"}).encode("utf-8")
            self.wfile.write(response_body)
            self.wfile.flush()
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
