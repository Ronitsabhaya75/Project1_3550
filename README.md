# JWKS Server
```
Name: Ronitkumar Sabhaya
EUID: rds0305
Email: ronitkumarsabhaya@my.unt.edu
CSCE 3550 Project1
```


# HTTP Authentication Server with JWKS Endpoint

This project implements an HTTP server that handles authentication and JWKS (JSON Web Key Set) endpoints. It supports the following features:

- RSA key generation
- JWT signing
- JWT token creation with an option for expired tokens
- Enforced HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD) for the `/auth` and `/.well-known/jwks.json` endpoints

## Features

- **RSA Key Generation**: The server can generate RSA key pairs (private and public) used for signing JWT tokens.
- **JWT Signing**: The server generates JWT tokens signed with RSA keys. The expiration time can be specified when generating the token.
- **JWKS Endpoint**: The server exposes a `/well-known/jwks.json` endpoint that returns the public keys in the JWKS format, including metadata such as key ID (kid), key type (kty), algorithm (alg), and usage (use).
- **Authentication Endpoint**: The server provides a `/auth` endpoint where JWT tokens can be generated with specific expiration times. If the `expired=true` query parameter is passed, an expired token is generated.

## Supported HTTP Methods

### `GET`

- `/well-known/jwks.json`: Returns the current JSON Web Key Set (JWKS) containing the public keys and metadata. Expired keys are filtered out.
  
### `POST`

- `/auth`: Generates a JWT token. You can specify if the token should be expired by passing the query parameter `expired=true`. If not specified, a valid token with a 10-minute expiration is created.

### `PUT`, `DELETE`, `PATCH`

- These methods are not allowed on the `/auth` and `/well-known/jwks.json` endpoints. A `405 Method Not Allowed` response will be returned.

### `HEAD`

- `/well-known/jwks.json`: Responds with a `200 OK` status and appropriate headers without sending the response body.

## How to Run the Server

1. Clone this repository.
2. install required libraries
3. Run the server:
    ```bash
    python server.py
    ```
4. The server will start on port `8080` by default. You can change the port by modifying the `PORT` variable in the `server.py` file.

## Endpoints

### `/auth`
- **Method**: `POST`
- **Description**: Generates a JWT token with a specified expiration time.
- **Query Parameters**:
  - `expired`: If `true`, an expired token is generated.
- **Response**:
  - JSON object containing the JWT token:
    ```json
    {
      "token": "<JWT_TOKEN>"
    }
    ```

### `/.well-known/jwks.json`
- **Method**: `GET`
- **Description**: Returns the JSON Web Key Set (JWKS) containing public keys and metadata.
- **Response**:
  - JSON object containing an array of keys:
    ```json
    {
      "keys": [
        {
          "kid": "<KEY_ID>",
          "kty": "RSA",
          "use": "sig",
          "alg": "RS256",
          "n": "<MODULUS>",
          "e": "<EXPONENT>"
        }
      ]
    }
    ```

## Dependencies

- `http.server`: For handling HTTP requests.
- `jwt`: For creating and verifying JWT tokens.
- `cryptography`: For RSA key generation and public key handling.



## ChatGPt and DeepSeek Promopts:
1.  Explain detail about Restful jwks server and relation of JWT and JWKS 
2.  Give me Sample code for jwks server
3.  Firstly error I got was my JWT token was not exprieing and I paste the error in GPT and told to change it to 10secs.
4.  Then Another error was Patch was found invalid I prompted to solve using HTTP server not FAST API to see if the error was still there but it wasnt resolved
5.  Prompoted to write the 10 unit test which explicitly test all parts of code.
