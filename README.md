# JWKS Server (Project 3 - Bulking Up JWKS with User Auth & Key Encryption)

This project enhances the JWKS server by implementing **AES encryption for private keys**, **user registration**, **authentication logging**, and an optional **rate limiter** to improve security and accountability.

## Features
- **AES-encrypted RSA private keys** stored securely in SQLite
- **User registration** with Argon2 password hashing and UUID-based password generation
- **Authentication logs** including timestamp, IP, and user ID
- Optional **rate limiting** (10 requests/second) for `/auth` endpoint
- **Test suite** for >90% coverage and **Gradebot compatible**

## Project Structure
```
  -------------- jwks_server --------------
                    |         
  --------------------------------------------
  |                 |                        |  
 server/          tests/                 (root files)
  |                 |                        |
  |                 |              --------------------------------
  |                 |             |      |       |     |           |
 __init__.py  test_jwks_server.py |    README.md |     |     gradebot and its ss
 db_manager.py                    run.py         |  SS of test Coverage
 jwks_server.py                            requirements.txt
```

## Installation & Setup

### Clone the Repository
```bash
git clone https://github.com/pradip676/Enhanced-JWKS-Auth-Server.git
cd Enhanced-JWKS-Auth-Server
```
### Prerequisites
Install required dependencies from `requirements.txt`:
```bash
pip install -r requirements.txt
```
or,
```bash
pip3 install -r requirements.txt
```

## Key Export (Before Running)
Before running the server, make sure to **export the AES key** as an environment variable:
(Run the follwoing command in the terminal)

### For MacOS/Linux
```bash
export NOT_MY_KEY="my_32_byte_secret_key_example__"
```
### For Windows PowerShell
```bash
$env:NOT_MY_KEY = "my_32_byte_secret_key_example__"  
```
### Windows CMD (Command Prompt)
```bash
set NOT_MY_KEY=my_32_byte_secret_key_example__  
```
> Note: If your key is shorter than 32 characters, it will be padded automatically.
> Required: AES key must be set for encryption/decryption of private keys.

## Linting
Check and follow PEP8 standards using flake8:
```bash
flake8 .
```

## Run the Server
```bash
python3 run.py
```
or,
```bash
python run.py
```
The server will be live at `http://127.0.0.1:8080`

## Endpoints

### 1. `/register`

- Method: `POST`
- Request JSON: `{ "username": "$MyCoolUsername", "email": "$MyCoolEmail" }`
- Returns: `{ "password": "$UUIDv4" }`
- Status Code: `200 OK` or `201 CREATED`
- Hashes the password using **Argon2** with configurable parameters
- Stores user in the `users` table securely

### 2. `/auth`

- Method: `POST`
- Returns: `{ "token": "JWT" }` if valid, or appropriate error response
- Optional: `?expired=true` to get an expired token
- Logs successful attempts to `auth_logs` table
- Returns 429 if rate-limited (if enabled)

### 3. `/.well-known/jwks.json`

- Method: `GET`
- Returns current valid public keys in JWKS format

### Invalid Methods

- All other methods (e.g., PUT, DELETE, PATCH) return 405

## Testing the Server Manually

### 1. Register a New User

```bash
curl -X POST http://127.0.0.1:8080/register -H "Content-Type: application/json" -d '{"username": "ps1093", "email": "ps1093@my.unt.edu"}'
```

Sample output:

```json
{
  "password": "f535a8569fca08502b691dd027a30fde"
}
```

### 2. Get a Valid JWT:

```bash
curl -X POST http://127.0.0.1:8080/auth -H "Content-Type: application/json" -d '{"username": "ps1093", "password": "f535a8569fca08502b691dd027a30fde"}'
```

Sample output:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3IiwidH..."
}
```

### 3. Get Public Keys (JWKS):

```bash
curl -X GET http://127.0.0.1:8080/.well-known/jwks.json
```

Sample output:

```json
{  
  "keys": [  
    {  
      "alg": "RS256",  
      "e": "AQAB",  
      "kid": "77",  
      "kty": "RSA",  
      "n": "462VILuvdgsCsceRIFujmB6PXHajkl9wYrf3BvX8...",  
      "use": "sig"  
    }  
  ]  
}
```

## Testing

### Run Tests

```bash
python -m pytest tests/
```
### Run Tests with Coverage
```bash
python -m pytest --cov=server --cov-report=term tests/
```

### Test Coverage Sample Output
```
platform darwin -- Python 3.12.5, pytest-8.3.4, pluggy-1.5.0
rootdir: /Users/pradipsapkota/Documents/Enhanced-JWKS-Auth-Server-1
plugins: cov-6.0.0, Faker-37.1.0
collected 11 items                                                                                                                                       

tests/test_jwks_server.py ...........  

---------- coverage: platform darwin, python 3.12.5-final-0 ----------
Name                    Stmts   Miss  Cover
-------------------------------------------
server/__init__.py          0      0   100%
server/db_manager.py       56      4    93%
server/jwks_server.py     114      5    96%
-------------------------------------------
TOTAL                     170      9    95%
```

## Run the test client (Gradebot)
```bash
./gradebot project3
```
Ensure the exported AES key is set before running gradebot. The client will verify key presence and DB setup.

### Sample Gradebot Output
```
╭────────────────────────────────────────────┬────────┬──────────┬─────────╮
│ RUBRIC ITEM                                │ ERROR? │ POSSIBLE │ AWARDED │
├────────────────────────────────────────────┼────────┼──────────┼─────────┤
│ Create users table                         │        │        5 │       5 │
│ /register endpoint                         │        │       20 │      20 │
│ Private Keys are encrypted in the database │        │       25 │      25 │
│ Create auth_logs table                     │        │        5 │       5 │
│ /auth requests are logged                  │        │       10 │      10 │
│ /auth is rate-limited (optional)           │        │       25 │      25 │
├────────────────────────────────────────────┼────────┼──────────┼─────────┤
│                                            │  TOTAL │       90 │      90 │
╰────────────────────────────────────────────┴────────┴──────────┴─────────╯
```

> AES key must be set in `NOT_MY_KEY` env variable before server or test run.

