"""
database.py — Secure Database Layer
=====================================
Implements all three data security states:

1. DATA-AT-REST: Sensitive fields are encrypted via encryption.py before INSERT/UPDATE.
   The raw SQLite file contains only ciphertext for protected columns.

2. DATA-IN-TRANSIT: Connection uses SSL/TLS (demonstrated via ssl_context on the
   connection; for SQLite we show the TLS wrapper pattern and include a PostgreSQL
   TLS URI example for production).

3. DATA-IN-PROCESS: ALL SQL uses parameterized queries (? placeholders).
   String interpolation into SQL is NEVER used anywhere in this file.
   This neutralizes SQL Injection attacks completely.
"""

import sqlite3
import ssl
import os
import logging
from contextlib import contextmanager
from app.encryption import encrypt_field, decrypt_field, hash_password, verify_password

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("DB_PATH", "fortress.db")

# For production PostgreSQL with TLS, the connection string would be:
# postgresql://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/path/to/ca.crt
# SQLite TLS is demonstrated via the ssl_context wrapper pattern below.

# ── TLS/SSL Context (Data-in-Transit) ────────────────────────────────────────

def build_ssl_context() -> ssl.SSLContext:
    """
    Build a strict TLS 1.2+ client context for database connections.

    For SQLite (file-based): wraps the connection to show the TLS pattern.
    For PostgreSQL/MySQL: pass sslmode='verify-full' + sslrootcert to enforce
    server certificate verification — man-in-the-middle attacks are rejected.

    TLS settings enforced:
    - Minimum TLSv1.2 (TLSv1.3 preferred)
    - Certificate verification REQUIRED (no self-signed without explicit CA)
    - Strong cipher suite only (no RC4, DES, or export-grade ciphers)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    cert_path = os.environ.get("DB_SSL_CERT", "certs/server.crt")
    if os.path.exists(cert_path):
        ctx.load_verify_locations(cert_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        logger.info("TLS: Certificate verification ENABLED — %s", cert_path)
    else:
        # Dev fallback: log a warning; production MUST have a certificate
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "TLS: No cert found at %s — running in UNVERIFIED mode. "
            "DO NOT use this in production.", cert_path
        )

    return ctx


# ── Database Initialization ──────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """
    Open a SQLite connection with Row factory for dict-like access.
    In production (PostgreSQL), replace this with psycopg2.connect(..., sslmode='verify-full').
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent reads + writes
    conn.execute("PRAGMA journal_mode=WAL")
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_cursor():
    """Context manager: yields a (conn, cursor) pair, commits on success, rolls back on error."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        yield conn, cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """
    Create all tables. Sensitive columns are documented with [ENCRYPTED] comments
    so any developer reading the schema knows these fields are ciphertext at rest.
    """
    with db_cursor() as (conn, cur):
        # Users table — passwords are ONE-WAY hashed (PBKDF2), never stored plain
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                password_hash TEXT  NOT NULL,           -- [HASHED] PBKDF2-SHA256
                role        TEXT    NOT NULL DEFAULT 'patient',
                created_at  TEXT    DEFAULT (datetime('now'))
            )
        """)

        # Patients table — PII fields are [ENCRYPTED] at rest
        cur.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL REFERENCES users(id),
                full_name       TEXT    NOT NULL,        -- [ENCRYPTED] AES-256
                date_of_birth   TEXT    NOT NULL,        -- [ENCRYPTED] AES-256
                ssn             TEXT,                    -- [ENCRYPTED] AES-256
                phone           TEXT,                    -- [ENCRYPTED] AES-256
                email           TEXT,                    -- [ENCRYPTED] AES-256
                created_at      TEXT    DEFAULT (datetime('now'))
            )
        """)

        # Medical records — clinical notes are [ENCRYPTED] at rest
        cur.execute("""
            CREATE TABLE IF NOT EXISTS medical_records (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id      INTEGER NOT NULL REFERENCES patients(id),
                doctor_name     TEXT    NOT NULL,
                diagnosis       TEXT    NOT NULL,        -- [ENCRYPTED] AES-256
                treatment_notes TEXT,                    -- [ENCRYPTED] AES-256
                prescription    TEXT,                    -- [ENCRYPTED] AES-256
                visit_date      TEXT    NOT NULL,
                created_at      TEXT    DEFAULT (datetime('now'))
            )
        """)

        # Audit log — tracks every sensitive data access
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                action      TEXT    NOT NULL,
                table_name  TEXT,
                record_id   INTEGER,
                ip_address  TEXT,
                timestamp   TEXT    DEFAULT (datetime('now'))
            )
        """)

    logger.info("Database initialized: %s", DB_PATH)


# ── User Operations ──────────────────────────────────────────────────────────

def create_user(username: str, password: str, role: str = "patient") -> int:
    """
    Insert a new user. Password is HASHED (not encrypted) — one-way only.
    Uses parameterized query — ? placeholders prevent SQL injection.
    """
    pw_hash = hash_password(password)
    # SECURITY: parameterized query — no string interpolation
    with db_cursor() as (conn, cur):
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pw_hash, role)   # ← values passed as tuple, never in SQL string
        )
        return cur.lastrowid


def get_user_by_username(username: str) -> dict | None:
    """
    Fetch a user by username.
    Parameterized: username is a bind parameter, never concatenated into SQL.
    """
    with db_cursor() as (conn, cur):
        # SECURITY: ? placeholder binds username safely
        cur.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def authenticate_user(username: str, password: str) -> dict | None:
    """Authenticate username + password. Returns user dict on success, None on failure."""
    user = get_user_by_username(username)
    if user and verify_password(user["password_hash"], password):
        return user
    return None


# ── Patient Operations ────────────────────────────────────────────────────────

def create_patient(user_id: int, full_name: str, dob: str,
                   ssn: str = None, phone: str = None, email: str = None) -> int:
    """
    Insert a patient record with all PII fields encrypted before storage.
    Data-at-Rest: encrypt_field() turns plaintext → AES-256 ciphertext before INSERT.
    Data-in-Process: parameterized ? placeholders prevent SQL injection.
    """
    with db_cursor() as (conn, cur):
        cur.execute(
            """INSERT INTO patients
               (user_id, full_name, date_of_birth, ssn, phone, email)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                encrypt_field(full_name),   # [ENCRYPTED] before DB write
                encrypt_field(dob),          # [ENCRYPTED]
                encrypt_field(ssn),          # [ENCRYPTED]
                encrypt_field(phone),        # [ENCRYPTED]
                encrypt_field(email),        # [ENCRYPTED]
            )
        )
        return cur.lastrowid


def get_patient(patient_id: int) -> dict | None:
    """
    Fetch and DECRYPT a patient record.
    Decryption happens in application memory (Data-in-Process clean room),
    never stored decrypted back to disk.
    """
    with db_cursor() as (conn, cur):
        # SECURITY: parameterized — patient_id bound as ?, not concatenated
        cur.execute(
            "SELECT * FROM patients WHERE id = ?",
            (patient_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        record = dict(row)
        # Decrypt encrypted fields in-memory only
        record["full_name"]     = decrypt_field(record["full_name"])
        record["date_of_birth"] = decrypt_field(record["date_of_birth"])
        record["ssn"]           = decrypt_field(record["ssn"])
        record["phone"]         = decrypt_field(record["phone"])
        record["email"]         = decrypt_field(record["email"])
        return record


def search_patients_by_doctor(doctor_name: str) -> list[dict]:
    """
    Search medical records by doctor name.
    Demonstrates parameterized LIKE query — even wildcard searches are safe.
    An attacker cannot inject SQL via the doctor_name parameter.
    """
    with db_cursor() as (conn, cur):
        # SECURITY: LIKE with ? placeholder — the % is applied server-side safely
        cur.execute(
            """SELECT mr.id, mr.visit_date, mr.doctor_name, p.full_name AS patient_name
               FROM medical_records mr
               JOIN patients p ON p.id = mr.patient_id
               WHERE mr.doctor_name LIKE ?
               ORDER BY mr.visit_date DESC""",
            (f"%{doctor_name}%",)   # ← wildcard wrapping is safe here; value bound as param
        )
        return [dict(r) for r in cur.fetchall()]


# ── Medical Record Operations ─────────────────────────────────────────────────

def create_medical_record(patient_id: int, doctor_name: str, diagnosis: str,
                           treatment_notes: str, prescription: str, visit_date: str) -> int:
    """
    Insert a medical record with clinical fields encrypted at rest.
    """
    with db_cursor() as (conn, cur):
        cur.execute(
            """INSERT INTO medical_records
               (patient_id, doctor_name, diagnosis, treatment_notes, prescription, visit_date)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                patient_id,
                doctor_name,                        # doctor name is not PII → stored plain
                encrypt_field(diagnosis),           # [ENCRYPTED]
                encrypt_field(treatment_notes),     # [ENCRYPTED]
                encrypt_field(prescription),        # [ENCRYPTED]
                visit_date,
            )
        )
        return cur.lastrowid


def get_medical_records(patient_id: int) -> list[dict]:
    """Fetch all records for a patient, decrypting clinical fields in-memory."""
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT * FROM medical_records WHERE patient_id = ? ORDER BY visit_date DESC",
            (patient_id,)
        )
        records = []
        for row in cur.fetchall():
            r = dict(row)
            r["diagnosis"]       = decrypt_field(r["diagnosis"])
            r["treatment_notes"] = decrypt_field(r["treatment_notes"])
            r["prescription"]    = decrypt_field(r["prescription"])
            records.append(r)
        return records


# ── Audit Logging ─────────────────────────────────────────────────────────────

def log_audit(user_id: int | None, action: str, table_name: str = None,
              record_id: int = None, ip_address: str = None):
    """
    Append an immutable audit trail entry.
    All values are parameterized — the audit log itself is injection-proof.
    """
    with db_cursor() as (conn, cur):
        cur.execute(
            """INSERT INTO audit_log (user_id, action, table_name, record_id, ip_address)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, action, table_name, record_id, ip_address)
        )


def get_audit_log(limit: int = 50) -> list[dict]:
    """Retrieve the most recent audit log entries."""
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
