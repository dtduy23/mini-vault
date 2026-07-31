# 🔐 Mini Vault

A lightweight, self-hosted secret manager inspired by [HashiCorp Vault](https://www.vaultproject.io/) and [AWS KMS](https://aws.amazon.com/kms/). Built with Python and FastAPI.

Mini Vault provides **encrypted-at-rest key-value storage** and a **Transit encryption & signing engine**, all protected by a single Master Passphrase and per-user authentication.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     FastAPI Server                       │
│  ┌──────────┐  ┌────────────┐  ┌───────────────────┐     │
│  │ Vault API│  │   KV API   │  │   Transit API     │     │
│  │  (0.1)   │  │ (1.1, 1.2) │  │ (2.1–2.4)         │     │
│  └────┬─────┘  └──────┬─────┘  └─────────┬─────────┘     │
│       │               │                  │               │
│  ┌────▼───────────────▼──────────────────▼──────────┐    │
│  │              Auth Guard (0.2)                    │    │
│  │       Session Token + Ownership Check            │    │
│  └────────────────────┬─────────────────────────────┘    │
│                       │                                  │
│  ┌────────────────────▼─────────────────────────────┐    │
│  │               VaultCore (0.1)                    │    │
│  │   Master Passphrase → Argon2id → KEK             │    │
│  │   KEK → AES-256-GCM → encrypts/decrypts DEK      │    │
│  │   DEK (in RAM only) → used by KV + Transit       │    │
│  └──────────────────────────────────────────────────┘    │
│                       │                                  │
│  ┌────────────────────▼─────────────────────────────┐    │
│  │              JsonStore (storage)                 │    │
│  │   Thread-safe, file-backed JSON persistence      │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### Encryption Flow

```
User Passphrase ──► Argon2id(salt) ──► KEK (256-bit)
                                         │
Random DEK (256-bit) ◄── AES-GCM decrypt ┘  (on unlock)
         │
         ├──► KV: AES-GCM(DEK, secret) → nonce + ciphertext + tag
         │
         ├──► Transit ENCRYPT_DECRYPT: AES-GCM(DEK, aes_key) → encrypted key at rest
         │         └──► AES-GCM(aes_key, plaintext) → vault:<name>:<b64>
         │
         └──► Transit SIGN_VERIFY: AES-GCM(DEK, private_key) → encrypted key at rest
                   └──► Ed25519/RSA sign(private_key, message) → signature
```

---

## 📁 Project Structure

```
Mini-vault/
├── README.md                 # This file
├── pyproject.toml            # Dependencies (managed with uv)
├── server.py                 # FastAPI server entry point
├── main.py                   # Standalone CLI for vault init/unlock demo
├── cli.py                    # Full CLI client (talks to server via HTTP)
├── demo_test.sh              # End-to-end demo script
├── src/
│   ├── core/                 # Feature 0.1: Master Passphrase, KDF, DEK
│   │   ├── vault.py          #   VaultCore — init, unlock, lock lifecycle
│   │   ├── kdf.py            #   Argon2id key derivation
│   │   └── crypto.py         #   AES-256-GCM encrypt/decrypt primitives
│   ├── auth/                 # Feature 0.2: User registration & login
│   │   └── service.py        #   AuthService — register, login, session tokens
│   ├── kv/                   # Feature 1: Secure KV Storage
│   │   └── service.py        #   KVService — encrypted write/read/delete
│   ├── transit/              # Feature 2: Encryption & Signing as a Service
│   │   └── service.py        #   TransitService — key mgmt, encrypt, sign
│   ├── storage/              # Persistence layer
│   │   └── json_store.py     #   Thread-safe JSON file storage
│   └── api/                  # FastAPI REST API
│       ├── app.py            #   Application factory
│       ├── deps.py           #   Dependency injection (singletons)
│       └── routes/           #   Route handlers for each feature
│           ├── vault.py
│           ├── auth.py
│           ├── kv.py
│           └── transit.py
├── tests/                    # Automated tests (pytest)
│   ├── test_vault_core.py    #   Feature 0.1 tests
│   ├── test_auth_service.py  #   Feature 0.2 tests (18 tests)
│   ├── test_kv_service.py    #   Features 1.1 & 1.2 tests (25 tests)
│   └── test_transit_service.py # Features 2.1–2.4 tests (30 tests)
├── data/                     # Runtime data (auto-created, gitignored)
│   ├── vault_meta.json       #   Encrypted DEK + KDF salt
│   ├── users/                #   User records (hashed passwords)
│   ├── sessions/             #   Active session tokens
│   ├── kv/                   #   Encrypted KV secrets
│   └── transit/              #   Encrypted named keys
└── docs/report/              # Project report
```

---

## 🚀 Getting Started

### Prerequisites

- **Python ≥ 3.13**
- **[uv](https://docs.astral.sh/uv/)** (recommended package manager)

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd Mini-vault

# Install dependencies with uv
uv sync
```

### Run the Server

```bash
# Start the FastAPI server
uv run python server.py

# Or with uvicorn directly (with hot-reload for development)
uv run uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
```

The server will start at `http://localhost:8000`. API documentation is available at `http://localhost:8000/docs` (Swagger UI).

### Run the Demo

```bash
# Start the server in one terminal, then in another:
bash demo_test.sh
```

This runs a full end-to-end test of all 8 features using `curl`.

### Run Tests

```bash
uv run python -m pytest tests/ -v
```

All 100 tests should pass.

---

## 🔧 Usage

### Option 1: CLI Client (`cli.py`)

The CLI client communicates with the running server via HTTP.

```bash
# ── Vault Lifecycle ──────────────────────────────────────
python cli.py vault init          # First run: set master passphrase
python cli.py vault unlock        # Decrypt DEK into RAM
python cli.py vault status        # Check initialized/unlocked
python cli.py vault lock          # Wipe DEK from RAM

# ── User Authentication ─────────────────────────────────
python cli.py auth register       # Create account (email + passphrase)
python cli.py auth login          # Login → saves token to .vault-token
python cli.py auth logout         # Invalidate session token

# ── KV Secrets ───────────────────────────────────────────
python cli.py kv write secret/alice@example.com/db '{"password":"s3cr3t"}'
python cli.py kv read  secret/alice@example.com/db
python cli.py kv delete secret/alice@example.com/db
python cli.py kv list

# ── Transit: Named Key Management ────────────────────────
python cli.py transit create-key my-aes-key
python cli.py transit create-key my-sign-key --type SIGN_VERIFY --algo ED25519
python cli.py transit create-key my-rsa-key --type SIGN_VERIFY --algo RSASSA_PKCS1_V1_5_SHA_256
python cli.py transit list-keys
python cli.py transit revoke-key my-aes-key

# ── Transit: Encrypt / Decrypt ───────────────────────────
python cli.py transit encrypt my-aes-key "Hello, world!"
python cli.py transit decrypt "vault:my-aes-key:<base64_blob>"

# ── Transit: Sign / Verify ───────────────────────────────
python cli.py transit sign   my-sign-key "message to sign"
python cli.py transit verify my-sign-key "message to sign" "<signature_b64>"
```

### Option 2: REST API (curl / Swagger)

```bash
# 1. Initialize vault
curl -X POST http://localhost:8000/vault/init \
  -H "Content-Type: application/json" \
  -d '{"master_passphrase": "MyStr0ngP@ssphrase!"}'

# 2. Unlock vault
curl -X POST http://localhost:8000/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"master_passphrase": "MyStr0ngP@ssphrase!"}'

# 3. Register user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Alice$ecure123","confirm_passphrase":"Alice$ecure123"}'

# 4. Login → get token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Alice$ecure123"}'
# Response: {"token": "mv_...", "expires_at": "..."}

# 5. Use token for all KV/Transit operations
TOKEN="mv_..."

# Write a secret
curl -X PUT http://localhost:8000/kv/secret/alice@example.com/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"data": {"username":"admin","password":"s3cr3t"}}'

# Read a secret
curl http://localhost:8000/kv/secret/alice@example.com/db \
  -H "Authorization: Bearer $TOKEN"

# Encrypt with Transit
curl -X POST http://localhost:8000/transit/encrypt/my-key \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plaintext_b64": "SGVsbG8gV29ybGQ="}'
```

Full API docs: `http://localhost:8000/docs`

---

## 🛡️ Security Features

### Cryptographic Primitives

| Purpose | Algorithm | Library |
| --------- | ----------- | --------- |
| Key derivation (Master Passphrase → KEK) | **Argon2id** (time=3, mem=64MiB) | `argon2-cffi` |
| Encryption at rest (DEK, KV, Transit keys) | **AES-256-GCM** (AEAD) | `cryptography` |
| Password hashing (user accounts) | **Argon2id** (OWASP defaults) | `argon2-cffi` |
| Digital signatures | **Ed25519** / **RSA-2048 PKCS#1 v1.5 SHA-256** | `cryptography` |
| Random generation (nonce, salt, keys) | `os.urandom` (CSPRNG) | stdlib |

### Security Guarantees

- **DEK never touches disk** — only the encrypted form is persisted; plaintext lives in RAM only while unlocked
- **Fresh nonce on every write** — AES-GCM nonce is never reused with the same key
- **AEAD integrity** — any tampering with ciphertext or tag is detected and rejected immediately
- **Ownership isolation** — User A cannot access User B's secrets or keys, even by guessing paths/names
- **Generic error messages** — wrong password vs. non-existent user are indistinguishable to prevent enumeration
- **Brute-force protection** — 5 consecutive failed logins → 5-minute account lockout
- **Session expiry** — tokens auto-expire after 30 minutes
- **Key material never exposed** — `list_keys()` API returns only metadata, never raw keys

---

## 📋 API Endpoints

### Vault (Feature 0.1)

| Method | Endpoint | Description |
| -------- | ---------- | ------------- |
| `POST` | `/vault/init` | Initialize vault (first run) |
| `POST` | `/vault/unlock` | Unlock vault with master passphrase |
| `POST` | `/vault/lock` | Lock vault (wipe DEK from RAM) |
| `GET` | `/vault/status` | Check initialized/unlocked state |

### Auth (Feature 0.2)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register new user |
| `POST` | `/auth/login` | Login → session token (30min TTL) |
| `POST` | `/auth/logout` | Invalidate session token |

### KV (Features 1.1 & 1.2)

| Method | Endpoint | Auth | Description |
| -------- | ---------- | ------ | ------------- |
| `PUT` | `/kv/{path}` | Bearer | Write secret (encrypted at rest) |
| `GET` | `/kv/{path}` | Bearer | Read secret (decrypt + verify tag) |
| `DELETE` | `/kv/{path}` | Bearer | Delete secret permanently |
| `GET` | `/kv/` | Bearer | List owned secret paths |

### Transit (Features 2.1–2.4)

| Method | Endpoint | Auth | Description |
| -------- | ---------- | ------ | ------------- |
| `POST` | `/transit/keys/{name}` | Bearer | Create named key |
| `GET` | `/transit/keys` | Bearer | List keys (metadata only) |
| `DELETE` | `/transit/keys/{name}` | Bearer | Revoke (delete) key |
| `POST` | `/transit/encrypt/{name}` | Bearer | Encrypt with named key |
| `POST` | `/transit/decrypt` | Bearer | Decrypt vault ciphertext |
| `POST` | `/transit/sign/{name}` | Bearer | Sign message |
| `POST` | `/transit/verify/{name}` | Bearer | Verify signature |

---

## 🧪 Test Coverage

```
tests/
├── test_vault_core.py       # 20 tests — init, unlock, lock, DEK lifecycle
├── test_auth_service.py     # 18 tests — register, login, lockout, tokens
├── test_kv_service.py       # 25 tests — CRUD, encryption, access control, tamper
└── test_transit_service.py  # 30 tests — keys, encrypt/decrypt, sign/verify, access
                             # ─────────
                             # 100 tests total — all passing ✅
```

```bash
# Run all tests
uv run python -m pytest tests/ -v

# Run a specific test file
uv run python -m pytest tests/test_kv_service.py -v
```

---

## 📦 Dependencies

| Package | Purpose |
| --------- | --------- |
| `cryptography` | AES-256-GCM, Ed25519, RSA-2048 |
| `argon2-cffi` | Argon2id KDF + password hashing |
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `pydantic[email]` | Request/response validation |
| `httpx` | CLI HTTP client |
| `pytest` | Unit testing (dev dependency) |

---

## 📝 License

This project is developed as a university coursework assignment.

## Video demo

<https://drive.google.com/drive/folders/1Kzn5NsBlYKQzEXBXSmgSqcqQfZ1fwHd6?usp=sharing>
