#!/usr/bin/env python3
"""
Mini Vault CLI — client that talks to the FastAPI server via HTTP.

Pattern: kubectl ↔ kubelet
  This CLI   ↔ Mini Vault server (uvicorn)

Usage examples:
  python cli.py vault init
  python cli.py vault unlock
  python cli.py vault lock
  python cli.py vault status

  python cli.py auth register
  python cli.py auth login
  python cli.py auth logout

  python cli.py kv write secret/alice@example.com/db '{"password":"abc123"}'
  python cli.py kv read  secret/alice@example.com/db
  python cli.py kv delete secret/alice@example.com/db
  python cli.py kv list

  python cli.py transit create-key my-aes-key
  python cli.py transit create-key my-sign-key --type SIGN_VERIFY --algo ED25519
  python cli.py transit list-keys
  python cli.py transit revoke-key my-aes-key

  python cli.py transit encrypt my-aes-key "hello world"
  python cli.py transit decrypt "vault:my-aes-key:..."

  python cli.py transit sign   my-sign-key "hello world"
  python cli.py transit verify my-sign-key "hello world" "<signature_b64>"
"""
import argparse
import base64
import getpass
import json
import sys
from pathlib import Path

import httpx

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL    = "http://localhost:8000"
TOKEN_FILE  = Path(".vault-token")   # saved in current directory


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _client() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, timeout=60.0)


def _load_token() -> str | None:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip() or None
    return None


def _save_token(token: str) -> None:
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)   # user-read-only


def _delete_token() -> None:
    TOKEN_FILE.unlink(missing_ok=True)


def _auth_headers() -> dict:
    token = _load_token()
    if not token:
        _die("Not logged in. Run: python cli.py auth login")
    return {"Authorization": f"Bearer {token}"}


def _die(msg: str, code: int = 1) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


def _ok(response: httpx.Response) -> dict:
    """Assert response is 2xx, pretty-print and return JSON body."""
    if response.is_success:
        try:
            data = response.json()
        except Exception:
            data = {}
        return data
    # Error path — show detail
    try:
        detail = response.json().get("detail", response.text)
    except Exception:
        detail = response.text
    _die(f"HTTP {response.status_code}: {detail}")


def _print(data: dict | list) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


# ── Vault commands ────────────────────────────────────────────────────────────

def cmd_vault_init(_args) -> None:
    passphrase = getpass.getpass("Choose a master passphrase (min 8 chars): ")
    confirm    = getpass.getpass("Confirm master passphrase: ")
    if passphrase != confirm:
        _die("Passphrases do not match")

    with _client() as c:
        r = c.post("/vault/init", json={"master_passphrase": passphrase})
    _print(_ok(r))
    print("→ Now run:  python cli.py vault unlock")


def cmd_vault_unlock(_args) -> None:
    passphrase = getpass.getpass("Master passphrase: ")
    with _client() as c:
        r = c.post("/vault/unlock", json={"master_passphrase": passphrase})
    _print(_ok(r))


def cmd_vault_lock(_args) -> None:
    with _client() as c:
        r = c.post("/vault/lock")
    _print(_ok(r))


def cmd_vault_status(_args) -> None:
    with _client() as c:
        r = c.get("/vault/status")
    _print(_ok(r))


# ── Auth commands ─────────────────────────────────────────────────────────────

def cmd_auth_register(_args) -> None:
    email   = input("Email: ").strip()
    pw      = getpass.getpass("Passphrase: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    with _client() as c:
        r = c.post("/auth/register", json={
            "email": email,
            "passphrase": pw,
            "confirm_passphrase": confirm,
        })
    _print(_ok(r))


def cmd_auth_login(_args) -> None:
    email = input("Email: ").strip()
    pw    = getpass.getpass("Passphrase: ")
    with _client() as c:
        r = c.post("/auth/login", json={"email": email, "passphrase": pw})
    data = _ok(r)
    _save_token(data["token"])
    print(f"✓ Logged in as {email}")
    print(f"  Token saved to {TOKEN_FILE}  (expires: {data['expires_at']})")


def cmd_auth_logout(_args) -> None:
    with _client() as c:
        r = c.post("/auth/logout", headers=_auth_headers())
    _ok(r)
    _delete_token()
    print("✓ Logged out. Token file deleted.")


# ── KV commands ───────────────────────────────────────────────────────────────

def cmd_kv_write(args) -> None:
    path = args.path
    # Accept raw string or JSON
    try:
        data = json.loads(args.data)
    except json.JSONDecodeError:
        data = args.data   # store as plain string

    with _client() as c:
        r = c.put(f"/kv/{path}", json={"data": data}, headers=_auth_headers())
    _print(_ok(r))


def cmd_kv_read(args) -> None:
    with _client() as c:
        r = c.get(f"/kv/{args.path}", headers=_auth_headers())
    data = _ok(r)
    # Pretty-print just the data value
    print(json.dumps(data.get("data", data), indent=2, ensure_ascii=False))


def cmd_kv_delete(args) -> None:
    with _client() as c:
        r = c.delete(f"/kv/{args.path}", headers=_auth_headers())
    _print(_ok(r))


def cmd_kv_list(_args) -> None:
    with _client() as c:
        r = c.get("/kv/", headers=_auth_headers())
    data = _ok(r)
    paths = data.get("paths", [])
    if not paths:
        print("(no secrets)")
    else:
        for p in paths:
            print(f"  {p}")


# ── Transit commands ──────────────────────────────────────────────────────────

def cmd_transit_create_key(args) -> None:
    body = {"key_usage": args.type}
    if args.algo:
        body["signing_algorithm"] = args.algo
    with _client() as c:
        r = c.post(f"/transit/keys/{args.key_name}", json=body, headers=_auth_headers())
    _print(_ok(r))


def cmd_transit_list_keys(_args) -> None:
    with _client() as c:
        r = c.get("/transit/keys", headers=_auth_headers())
    data = _ok(r)
    keys = data.get("keys", [])
    if not keys:
        print("(no keys)")
    else:
        for k in keys:
            algo = f"  algo={k['signing_algorithm']}" if k.get("signing_algorithm") else ""
            print(f"  {k['key_name']}  [{k['key_usage']}]{algo}")


def cmd_transit_revoke_key(args) -> None:
    confirm = input(f"Revoke key '{args.key_name}'? This cannot be undone. [y/N] ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return
    with _client() as c:
        r = c.delete(f"/transit/keys/{args.key_name}", headers=_auth_headers())
    _print(_ok(r))


def cmd_transit_encrypt(args) -> None:
    # Encode plaintext as base64
    plaintext_b64 = base64.b64encode(args.plaintext.encode()).decode()
    with _client() as c:
        r = c.post(f"/transit/encrypt/{args.key_name}",
                   json={"plaintext_b64": plaintext_b64},
                   headers=_auth_headers())
    data = _ok(r)
    print(data.get("ciphertext", ""))


def cmd_transit_decrypt(args) -> None:
    with _client() as c:
        r = c.post("/transit/decrypt",
                   json={"ciphertext": args.ciphertext},
                   headers=_auth_headers())
    data = _ok(r)
    pt_b64 = data.get("plaintext_b64", "")
    plaintext = base64.b64decode(pt_b64).decode(errors="replace")
    print(plaintext)


def cmd_transit_sign(args) -> None:
    message_b64 = base64.b64encode(args.message.encode()).decode()
    with _client() as c:
        r = c.post(f"/transit/sign/{args.key_name}",
                   json={"message_b64": message_b64, "message_type": "RAW"},
                   headers=_auth_headers())
    data = _ok(r)
    print(f"Signature ({data.get('signing_algorithm', '')}):")
    print(data.get("signature_b64", ""))


def cmd_transit_verify(args) -> None:
    message_b64 = base64.b64encode(args.message.encode()).decode()
    with _client() as c:
        r = c.post(f"/transit/verify/{args.key_name}",
                   json={
                       "message_b64":   message_b64,
                       "message_type":  "RAW",
                       "signature_b64": args.signature,
                   },
                   headers=_auth_headers())
    data = _ok(r)
    valid = data.get("signature_valid", False)
    icon  = "✓" if valid else "✗"
    print(f"{icon} signature_valid: {valid}  (algorithm: {data.get('signing_algorithm', '?')})")


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vault",
        description="Mini Vault CLI — secure secret manager",
    )
    sub = p.add_subparsers(dest="group", required=True)

    # ── vault ─────────────────────────────────────────────────────────────────
    g_vault = sub.add_parser("vault", help="Vault lifecycle (Feature 0.1)")
    s_vault = g_vault.add_subparsers(dest="cmd", required=True)
    s_vault.add_parser("init",   help="Initialize vault (first run)")
    s_vault.add_parser("unlock", help="Unlock vault (DEK → RAM)")
    s_vault.add_parser("lock",   help="Lock vault (wipe DEK from RAM)")
    s_vault.add_parser("status", help="Show vault status")

    # ── auth ──────────────────────────────────────────────────────────────────
    g_auth = sub.add_parser("auth", help="User auth (Feature 0.2)")
    s_auth = g_auth.add_subparsers(dest="cmd", required=True)
    s_auth.add_parser("register", help="Register new account")
    s_auth.add_parser("login",    help="Login and save token")
    s_auth.add_parser("logout",   help="Logout and delete token")

    # ── kv ────────────────────────────────────────────────────────────────────
    g_kv = sub.add_parser("kv", help="KV secrets (Feature 1)")
    s_kv = g_kv.add_subparsers(dest="cmd", required=True)

    p_write = s_kv.add_parser("write", help="Write a secret")
    p_write.add_argument("path", help='e.g. secret/alice@example.com/db')
    p_write.add_argument("data", help='JSON or plain string value')

    p_read = s_kv.add_parser("read", help="Read a secret")
    p_read.add_argument("path")

    p_del = s_kv.add_parser("delete", help="Delete a secret")
    p_del.add_argument("path")

    s_kv.add_parser("list", help="List your secrets")

    # ── transit ───────────────────────────────────────────────────────────────
    g_tr = sub.add_parser("transit", help="Transit engine (Feature 2)")
    s_tr = g_tr.add_subparsers(dest="cmd", required=True)

    p_ck = s_tr.add_parser("create-key", help="Create a named key")
    p_ck.add_argument("key_name")
    p_ck.add_argument("--type", default="ENCRYPT_DECRYPT",
                      choices=["ENCRYPT_DECRYPT", "SIGN_VERIFY"])
    p_ck.add_argument("--algo", default=None,
                      choices=["ED25519", "RSASSA_PKCS1_V1_5_SHA_256"])

    s_tr.add_parser("list-keys",  help="List your named keys")

    p_rk = s_tr.add_parser("revoke-key", help="Permanently delete a key")
    p_rk.add_argument("key_name")

    p_enc = s_tr.add_parser("encrypt", help="Encrypt plaintext with a named key")
    p_enc.add_argument("key_name")
    p_enc.add_argument("plaintext", help="Plaintext string to encrypt")

    p_dec = s_tr.add_parser("decrypt", help="Decrypt a vault ciphertext")
    p_dec.add_argument("ciphertext", help='vault:<key>:<b64>')

    p_sign = s_tr.add_parser("sign", help="Sign a message")
    p_sign.add_argument("key_name")
    p_sign.add_argument("message")

    p_verify = s_tr.add_parser("verify", help="Verify a signature")
    p_verify.add_argument("key_name")
    p_verify.add_argument("message")
    p_verify.add_argument("signature", help="base64-encoded signature")

    return p


# ── Dispatch ──────────────────────────────────────────────────────────────────

DISPATCH = {
    ("vault",   "init"):        cmd_vault_init,
    ("vault",   "unlock"):      cmd_vault_unlock,
    ("vault",   "lock"):        cmd_vault_lock,
    ("vault",   "status"):      cmd_vault_status,
    ("auth",    "register"):    cmd_auth_register,
    ("auth",    "login"):       cmd_auth_login,
    ("auth",    "logout"):      cmd_auth_logout,
    ("kv",      "write"):       cmd_kv_write,
    ("kv",      "read"):        cmd_kv_read,
    ("kv",      "delete"):      cmd_kv_delete,
    ("kv",      "list"):        cmd_kv_list,
    ("transit", "create-key"):  cmd_transit_create_key,
    ("transit", "list-keys"):   cmd_transit_list_keys,
    ("transit", "revoke-key"):  cmd_transit_revoke_key,
    ("transit", "encrypt"):     cmd_transit_encrypt,
    ("transit", "decrypt"):     cmd_transit_decrypt,
    ("transit", "sign"):        cmd_transit_sign,
    ("transit", "verify"):      cmd_transit_verify,
}


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    key    = (args.group, args.cmd)
    fn     = DISPATCH.get(key)
    if fn is None:
        parser.print_help()
        sys.exit(1)
    fn(args)


if __name__ == "__main__":
    main()
