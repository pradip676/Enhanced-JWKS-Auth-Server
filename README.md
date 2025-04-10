# JWKS Server (Project 3 - Enhanced Version with AES Encryption)

This project further extends the JWKS authentication server by requiring **pre-exported keys** for secure startup. It supports AES-encrypted private key storage in SQLite and enforces key availability before operation.

## Features
- **SQLite-backed encrypted key storage** using AES-GCM
- **RSA key export requirement before runtime**
- **JWT signing** with securely stored private keys
- **Secure RESTful API** for auth and JWKS retrieval
- **Comprehensive test suite** for full feature validation
- **Gradebot compatible** for automatic testing and grading

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

### Prerequisites
Install required dependencies from `requirements.txt`:
```bash
pip install -r requirements.txt
```
or,
```bash
pip3 install -r requirements.txt
```

### Clone the Repository
```bash
git clone https://github.com/pradip676/Enhanced-JWKS-Auth-Server.git
cd Enhanced-JWKS-Auth-Server
```

## Key Export (Before Running)
Before running the server, make sure to **export the AES key** as an environment variable:

```bash
export NOT_MY_KEY="11821781"  # or use a stronger 32-character key
```

> Note: If your key is shorter than 32 characters, it will be padded automatically.

## Linting
Check and follow PEP8 standards using flake8:
```bash
flake8 .
```

## Run the Server
```bash
python3 run.py
```
The server will be live at `http://127.0.0.1:8080`

## Endpoints

### 1. JWKS Endpoint
- `GET /.well-known/jwks.json` – Returns all valid public keys
- Invalid methods (POST, PUT, DELETE, PATCH) – `405 Method Not Allowed`

### 2. Authentication Endpoint
- `POST /auth` – Issues a JWT if user exists and credentials are correct
- `POST /auth?expired=true` – Returns expired JWT for testing
- Invalid methods (GET, PUT, DELETE, PATCH) – `405 Method Not Allowed`

## Testing the Server Manually

### 1. Get a JWT
```bash
curl -X POST http://127.0.0.1:8080/auth \
     -H "Content-Type: application/json" \
     -d '{"username": "userABC", "password": "yourpassword"}'
```

### 2. Get JWKS
```bash
curl -X GET http://127.0.0.1:8080/.well-known/jwks.json
```

## Testing

### Run Tests with Coverage
```bash
python3 -m pytest --cov=server --cov-report=term tests/
```

### Test Coverage Sample Output
```
platform darwin -- Python 3.12.5, pytest-8.3.4, pluggy-1.5.0
rootdir: /Users/pradipsapkota/Documents/Enhanced-JWKS-Auth-Server
plugins: cov-6.0.0
collected 11 items

tests/test_jwks_server.py ...........

---------- coverage: platform darwin, python 3.12.5-final-0 ----------
Name                    Stmts   Miss  Cover
-------------------------------------------
server/__init__.py          0      0   100%
server/db_manager.py       54      3    94%
server/jwks_server.py     111      5    95%
-------------------------------------------
TOTAL                     165      8    95%
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

