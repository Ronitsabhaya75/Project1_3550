# JWKS Server - Project-3
```
Name: Ronitkumar Sabhaya
EUID: rds0305
Email: ronitkumarsabhaya@my.unt.edu
CSCE 3550 - Foundations of Cyber Security
Project 3 - Extending the JWKS Server
```

## Overview

Completing the project 3 jwks server

## Steps to install and run the program

step-0:
```bash
git clone https://github.com/Ronitsabhaya75/Project1_3550.git
```

step-1: install dependency
```bash
pip3 install -r requirements.txt 
```

step2: export wy key
```bash
export NOT_WY_KEY="your key" 
```

step3: start program
```bash
python3 main.py
```

step4: testing
```bash
python3 -m unittest test_Project3.py -v
```

step5: linting
```bash
pylint main.py
```

## AI Prompts:
1. fix the code with requirements
2. First error ``` Private Keys are encrypted in the database │ sql: Scan error on column index 2, name "exp": converting driver.Value type float64 ("1.743977258595126e+09") to a int64: invalid syntax │       25 │       0 ```
3. Second error ```/auth requests are logged                  │ no logs found │       10 │       0 ```
4. Third error ```/auth is rate-limited (optional)           │        │       25 │       0 │```
5. Fourth error ```/auth requests are logged                  │ missing destination name status_code in *[]main.authLog │       10 │       0 ```
6. Fourth error ```time=2025-04-19T14:49:24.684-05:00 level=ERROR msg="/auth requests are logged" err="missing destination name status_code in *[]main.authLog"```



# JWKS Server - Project-2

```
Name: Ronitkumar Sabhaya
EUID: rds0305
Email: ronitkumarsabhaya@my.unt.edu
CSCE 3550 - Foundations of Cyber Security
Project 2 - Extending the JWKS Server
```

## Overview

This project extends the basic JWKS Server from Project 1 by adding a SQLite database to store and manage JSON Web Keys (JWKs) and JSON Web Tokens (JWTs). The server supports RSA key generation, JWT signing, and proper HTTP method enforcement. It provides endpoints for generating JWTs and retrieving public keys in JWKS format.

---

### 1. Setup
#### Prequisites
1. Python 3.11+
2. Required Python packages: cryptography, pyjwt, sqlite3

#### Installation: 

```bash
git clone https://github.com/Ronitsabhaya75/Project1_3550.git
``` 

```bash
cd Project1_3550
```

install all dependecy library such cryptography pyjwt sqlite3 http.server time


--------------------------------------------------------------------------------

Run this program using
```bash
python3 sample.py
```

--------------------------------------------------------------------------------

**Test Client**
Make sure to run the test client on a separate IDE or Terminal instance!
```bash
python3 test_Project2.py 
```

## ChatGPt and DeepSeek Promopts:
1.  Detail explaination of connecting sqlite3 database
2.  How will RSA key will look like and how to insert 
3.  Give me Sample code integrating with sample server
4.  Frist error : ```Valid JWK found in JWKS        │ unexpected end of JSON input │       20 │       0 │```
5.  Second error: ```│ Valid JWK found in JWKS        │ token is unverifiable: error while executing keyfunc: the given key ID was not found in the JWKS │       20 │       0 │```
6.  Third error: ```│ Valid JWK found in JWKS        │ token is malformed: could not base64 decode header: illegal base64 data at input byte 0 │       20 │       0 ```
7.  Prompoted to write the 9 unit test which explicitly test all parts of code.




# JWKS Server -  Project1
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
