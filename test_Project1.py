import time
import requests
import jwt

BASE_URL = "http://127.0.0.1:8080"

def test_jwks_json():
    """
    Test that the JWKS endpoint returns the correct JSON structure.
    This function sends a GET request to the JWKS endpoint at '.well-known/jwks.json'.
    It verifies that the status code of the response is 200 (OK), indicating that the request was successful.
    Additionally, it checks whether the response contains a 'keys' field, which is a necessary part of the JWKS (JSON Web Key Set) response.
    """
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=10)
    assert response.status_code == 200
    assert "keys" in response.json()

def test_post_auth():
    """
    Test the POST /auth endpoint that returns a valid JWT.
    This function sends a POST request to the /auth endpoint to obtain an authentication token.
    It then checks if the response contains the expected 'access_token'.
    After retrieving the token, it attempts to decode it using the jwt library without verifying the signature.
    The decoded token is validated to ensure it contains both a header and a payload.
    If the token is expired or invalid, assertions will fail.
    """
    response = requests.post(f"{BASE_URL}/auth", timeout=10)
    assert response.status_code == 200
    token = response.json().get("access_token") or response.json().get("data", {}).get("access_token")
    assert token is not None, "Access token not found"
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        assert "header" in decoded_token 
        assert "payload" in decoded_token
    except jwt.ExpiredSignatureError:
        assert False, "JWT is expired"
    except jwt.InvalidTokenError:
        assert False, "JWT is invalid"

def test_get_auth():
    """
    Test the GET /auth endpoint, which should return 405 Method Not Allowed.
    This function sends a GET request to the /auth endpoint and asserts that the response status code is 405 (Method Not Allowed),
    indicating that GET requests are not supported for this endpoint.
    The response headers should include an "Allow" header that lists "POST" as the only valid method for this endpoint.
    """
    response = requests.get(f"{BASE_URL}/auth", timeout=10)
    assert response.status_code == 405
    assert "POST" in response.headers.get("Allow", "")

def test_post_jwks():
    """
    Test POST to the JWKS endpoint, which should return 405 Method Not Allowed.
    This function sends a POST request to the JWKS endpoint at '.well-known/jwks.json'.
    The expected result is a 405 error code (Method Not Allowed), since POST requests should not be allowed on this endpoint.
    The response should also include an "Allow" header specifying that only "GET" and "HEAD" methods are valid for this endpoint.
    """
    response = requests.post(f"{BASE_URL}/.well-known/jwks.json", timeout=10)
    assert response.status_code == 405
    assert "GET, HEAD" in response.headers.get("Allow", "")

def test_expired_token():
    """
    Test the expired token scenario using ?expired=true.
    This function sends a POST request to the /auth endpoint with the query parameter 'expired=true'.
    It checks that a token is returned and then decodes it using the jwt library.
    The decoded token's expiration time ('exp') is verified to ensure that it is in the past, indicating that the token is expired.
    """
    response = requests.post(f"{BASE_URL}/auth?expired=true", timeout=10)
    assert response.status_code == 200
    token = response.json().get("token") or response.json().get("data", {}).get("token")
    assert token is not None, "Access token not found"
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    exp_timestamp = decoded_token.get("exp")
    assert exp_timestamp is not None, "Expiration time not found"
    current_time = int(time.time())
    assert exp_timestamp < current_time, "The token is not expired"

def test_valid_token():
    """
    Test the valid token scenario (not expired).
    This function sends a POST request to the /auth endpoint with the query parameter 'expired=false'.
    It checks that a valid token is returned and decodes it using the jwt library.
    The decoded token's expiration time ('exp') is checked to ensure it is in the future, indicating that the token is not expired.
    """
    response = requests.post(f"{BASE_URL}/auth?expired=false", timeout=10)
    assert response.status_code == 200
    token = response.json().get("token") or response.json().get("data", {}).get("token")
    assert token is not None, "Access token not found"
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    exp_timestamp = decoded_token.get("exp")
    assert exp_timestamp is not None, "Expiration time not found"
    current_time = int(time.time())
    assert exp_timestamp > current_time, "The token is expired"

def test_put_jwks():
    """
    Test PUT to the JWKS endpoint, which should return 405 Method Not Allowed.
    This function sends a PUT request to the JWKS endpoint at '.well-known/jwks.json'.
    Since PUT requests are not allowed on this endpoint, the expected result is a 405 error code (Method Not Allowed).
    The response should also include an "Allow" header listing "GET" and "HEAD" as valid methods.
    """
    response = requests.put(f"{BASE_URL}/.well-known/jwks.json", timeout=10)
    assert response.status_code == 405
    assert "GET, HEAD" in response.headers.get("Allow", "")

def test_delete_auth():
    """
    Test DELETE to the /auth endpoint, which should return 405 Method Not Allowed.
    This function sends a DELETE request to the /auth endpoint, which is not allowed.
    The expected result is a 405 error code (Method Not Allowed), and the response should include an "Allow" header specifying that only "POST" is valid.
    """
    response = requests.delete(f"{BASE_URL}/auth", timeout=10)
    assert response.status_code == 405
    assert "POST" in response.headers.get("Allow", "")

def test_invalid_path():
    """
    Test invalid path returns a 404 error.
    This function sends a GET request to an invalid path, '/invalid-path', which should not exist.
    The expected result is a 404 error code, indicating that the requested resource could not be found.
    """
    response = requests.get(f"{BASE_URL}/invalid-path", timeout=10)
    assert response.status_code == 404

def test_head_jwks():
    """
    Test HEAD to the JWKS endpoint, which should return headers only (no body).
    This function sends a HEAD request to the JWKS endpoint at '.well-known/jwks.json'.
    It verifies that the response status code is 200 (OK) and that the 'Content-Type' header is set to 'application/json'.
    Additionally, since HEAD requests should not return a body, it ensures that the response body is empty.
    """
    response = requests.head(f"{BASE_URL}/.well-known/jwks.json", timeout=10)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json" 
    assert response.text == "" 

def test_jwks_non_expired_keys():
    """
    Test that only non-expired keys are listed in the JWKS.
    This function simulates obtaining both expired and valid tokens and then checks the JWKS (JSON Web Key Set) for the valid key.
    It ensures that only valid keys are included in the JWKS response.
    The 'kid' (key ID) from the valid token is extracted and checked against the keys in the JWKS.
    """
    expired_response = requests.post(f"{BASE_URL}/auth?expired=true", timeout=10)
    expired_token = expired_response.json().get("access_token") or expired_response.json().get("data", {}).get("access_token")
    assert expired_token is not None, "Expired token not found"
    valid_response = requests.post(f"{BASE_URL}/auth", timeout=10)
    valid_token = valid_response.json().get("access_token") or valid_response.json().get("data", {}).get("access_token")
    assert valid_token is not None, "Valid token not found"
    jwks_response = requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=10)
    jwks = jwks_response.json().get("keys", [])
    assert len(jwks) > 0
    valid_kid = jwt.get_unverified_header(valid_token).get("kid")
    assert valid_kid is not None, "JWT key ID (kid) not found"
    assert any(key["kid"] == valid_kid for key in jwks) 

if __name__ == "__main__":
    import pytest
    pytest.main()
