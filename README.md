# 🏰 Fortress DB — Medical Records Management System

A secure, database-driven medical records API demonstrating enterprise-grade protection across all three critical data states: **at-rest**, **in-transit**, and **in-process**.

Built with Python, Flask, and SQLite (PostgreSQL-ready). All sensitive data (patient PII, clinical notes, prescriptions) is protected end-to-end.

---

## 📋 Security Architecture Summary

| Data State | Security Control | Implementation |
|---|---|---|
| **At-Rest** | AES-256 Field-Level Encryption | `cryptography.Fernet` — sensitive DB columns store ciphertext, not plaintext |
| **In-Transit** | TLS 1.2+ with Certificate Verification | `ssl.SSLContext(TLS_CLIENT)` · PostgreSQL `sslmode=verify-full` |
| **In-Process** | Parameterized Queries (Prepared Statements) | `sqlite3` `?` placeholders — zero string interpolation in SQL |

---

## 🛡️ Security State Deep Dive

### 1. Data-at-Rest — The Vault

**Threat:** An attacker steals or dumps the `.db` database file.  
**Protection:** AES-256 symmetric encryption on every sensitive column. Without the encryption key, all PII is unreadable ciphertext.

**Encrypted fields:**

| Table | Field | Why Encrypted |
|---|---|---|
| `patients` | `full_name` | HIPAA PII |
| `patients` | `date_of_birth` | HIPAA PII |
| `patients` | `ssn` | Identity theft risk |
| `patients` | `phone` | PII |
| `patients` | `email` | PII |
| `medical_records` | `diagnosis` | Protected Health Information |
| `medical_records` | `treatment_notes` | Protected Health Information |
| `medical_records` | `prescription` | Protected Health Information |
| `users` | `password_hash` | One-way PBKDF2 hash (480,000 iterations) |

**What the database actually contains:**

```
-- Raw SQLite dump (attacker's view):
full_name: ENCRYPTED:gAAAAABmXn4z9k8LpQ2vRr7mNsC...
ssn:       ENCRYPTED:gAAAAABmXn4z1a2B3c4D5e6F7g8...
diagnosis: ENCRYPTED:gAAAAABmXn4zAbCdEfGhIjKlMn...
```

**Key management** (`app/encryption.py`):
- Keys loaded from environment variables — never hardcoded in source
- Key derivation: PBKDF2-HMAC-SHA256 (480,000 iterations, OWASP 2024 recommendation)
- Random IV per encryption → identical values produce different ciphertext (prevents frequency analysis)

---

### 2. Data-in-Transit — The Secure Tunnel

**Threat:** A man-in-the-middle attacker intercepts database traffic on the network.  
**Protection:** TLS 1.2+ encrypted channel between application and database server.

**TLS Configuration** (`app/database.py → build_ssl_context()`):

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # TLS 1.0/1.1 rejected
ctx.load_verify_locations("certs/server.crt")   # CA certificate loaded
ctx.verify_mode = ssl.CERT_REQUIRED              # Server cert MUST be valid
```

**For production PostgreSQL**, the connection string enforces TLS at the driver level:

```
postgresql://user:pass@db.host:5432/medical_db
  ?sslmode=verify-full          ← rejects self-signed/untrusted certs
  &sslrootcert=/etc/ssl/ca.crt  ← CA certificate path
```

`sslmode=verify-full` means:
- ✅ The connection is encrypted
- ✅ The server's certificate is signed by a trusted CA
- ✅ The certificate's hostname matches the server — MITM attacks rejected

---

### 3. Data-in-Process — The Clean Room

**Threat:** SQL injection via malicious user input.  
**Protection:** 100% parameterized queries using `?` placeholders. User input is **never** concatenated into SQL strings.

**Vulnerable pattern (what we DON'T do):**
```python
# ❌ NEVER — allows SQL injection
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**Safe pattern (what we DO everywhere):**
```python
# ✅ ALWAYS — input bound as data, not SQL
cursor.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)   # passed as a separate tuple
)
```

**Attacks blocked by parameterization:**

| Attack Type | Payload | Result |
|---|---|---|
| Tautology | `' OR '1'='1` | Treated as literal string → no match |
| Comment bypass | `admin' --` | Treated as literal string → no match |
| UNION extraction | `x' UNION SELECT password_hash FROM users --` | Treated as literal string |
| Destructive | `'; DROP TABLE patients; --` | Treated as literal string → table survives |
| LIKE injection | `%'; SELECT * FROM users; --` | Treated as literal string |

All of these are proven in `tests/test_security.py`.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/fortress-db.git
cd fortress-db

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
# Edit .env — set DB_ENCRYPTION_PASSWORD and DB_ENCRYPTION_SALT
```

Generate a Fernet key for production:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Paste the output as `DB_ENCRYPTION_KEY` in your `.env`.

### Run the Application

```bash
python app.py
# Server starts at http://localhost:5000
```

### Run the Security Tests

```bash
python -m pytest tests/test_security.py -v
```

All 14 tests prove the three security states are working correctly.

---

## 🔌 API Reference

All endpoints are prefixed with `/api`.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/register` | Register a new user |
| `POST` | `/api/login` | Authenticate and get user info |

### Patients

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/patients` | Create a patient (PII encrypted at rest) |
| `GET` | `/api/patients/<id>` | Fetch a patient (decrypted in-memory) |
| `GET` | `/api/patients/search?doctor=<name>` | Search by doctor (parameterized LIKE) |

### Medical Records

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/records` | Add a medical record (clinical data encrypted) |
| `GET` | `/api/records/<patient_id>` | Get all records for a patient |

### Utilities

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/security/demo` | Live proof of all three security states |
| `GET` | `/api/audit` | View audit trail |

### Example Requests

```bash
# Register a user
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"drsmith","password":"securePass123!","role":"doctor"}'

# Create a patient (PII will be AES-256 encrypted in the DB)
curl -X POST http://localhost:5000/api/patients \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "full_name": "Jane Doe",
    "date_of_birth": "1975-08-22",
    "ssn": "555-44-3333",
    "email": "jane@example.com"
  }'

# Inspect security state live
curl http://localhost:5000/api/security/demo

# Test SQL injection resistance (safe — parameterized)
curl "http://localhost:5000/api/patients/search?doctor=%27%3B+DROP+TABLE+patients%3B+--"
```

---

## 📁 Project Structure

```
fortress-db/
├── app.py                  # Flask entry point, security headers
├── app/
│   ├── encryption.py       # AES-256 encrypt/decrypt, PBKDF2 password hashing
│   ├── database.py         # DB layer: TLS context, parameterized queries, encryption
│   └── routes.py           # Flask API blueprints
├── tests/
│   └── test_security.py    # 14 automated security tests
├── certs/                  # TLS certificate directory (add server.crt here)
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## ✅ Security Test Results

```
tests/test_security.py::TestDataAtRest::test_encrypt_produces_ciphertext          PASSED
tests/test_security.py::TestDataAtRest::test_decrypt_recovers_original             PASSED
tests/test_security.py::TestDataAtRest::test_different_encryptions_of_same_value  PASSED
tests/test_security.py::TestDataAtRest::test_password_is_hashed_not_encrypted     PASSED
tests/test_security.py::TestDataAtRest::test_db_stores_ciphertext_not_plaintext   PASSED
tests/test_security.py::TestDataInTransit::test_tls_context_minimum_version       PASSED
tests/test_security.py::TestDataInTransit::test_no_weak_ciphers                   PASSED
tests/test_security.py::TestDataInTransit::test_production_postgresql_tls_uri     PASSED
tests/test_security.py::TestDataInProcess::test_classic_tautology_injection_on_login  PASSED
tests/test_security.py::TestDataInProcess::test_comment_based_injection           PASSED
tests/test_security.py::TestDataInProcess::test_union_based_injection             PASSED
tests/test_security.py::TestDataInProcess::test_drop_table_injection              PASSED
tests/test_security.py::TestDataInProcess::test_no_dynamic_sql_in_codebase        PASSED
tests/test_security.py::TestIntegration::test_full_patient_lifecycle_is_secure    PASSED
```

---

## 🔒 Production Checklist

Before deploying this to a real environment:

- [ ] Replace `DB_ENCRYPTION_KEY` with a production-generated Fernet key
- [ ] Set up PostgreSQL with `sslmode=verify-full` and a real CA certificate
- [ ] Place the CA certificate at `certs/server.crt`
- [ ] Set `FLASK_DEBUG=false`
- [ ] Generate a strong `FLASK_SECRET_KEY`
- [ ] Run behind a reverse proxy (nginx/Caddy) with HTTPS
- [ ] Enable database-level encryption (PostgreSQL: `pgcrypto` extension)
- [ ] Rotate encryption keys periodically using MultiFernet key rotation

---

## 📚 References

- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-111: Storage Encryption](https://csrc.nist.gov/publications/detail/sp/800-111/final)
- [cryptography.io Fernet Documentation](https://cryptography.io/en/latest/fernet/)
- [PostgreSQL SSL Configuration](https://www.postgresql.org/docs/current/ssl-tcp.html)

---

## 📄 License

MIT License — see `LICENSE` for details.
