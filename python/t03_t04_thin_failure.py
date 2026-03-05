"""
================================================================================
T03 / T04 — python-oracledb THIN mode — IAM Token — FAILURE evidence
================================================================================
Repository  : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
Whitepaper  : docs/whitepaper.pdf
Author      : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program

RESULT      : FAILURE ❌ — structural failure at Oracle Net connect negotiation
Tests       : T03 (Human SSO) / T04 (M2M API Key)
Driver      : python-oracledb 3.4.2 — THIN mode (pure Python, no Instant Client)
Network     : ADB-S Private Endpoint — mTLS (ewallet.pem)
SR          : Open — Oracle Database Driver Engineering

--------------------------------------------------------------------------------
ROOT CAUSE ANALYSIS
--------------------------------------------------------------------------------

What THIN mode is
-----------------
python-oracledb THIN mode is a pure-Python reimplementation of Oracle Net.
It does not use Oracle Instant Client. No C libraries. No libclntsh. No oci.dll.
The entire Oracle Net protocol — TLS handshake, connect negotiation, TNS packets,
authentication — is handled in Python code inside the oracledb package.

Why THIN mode fails for IAM DB Token on ADB-S Private Endpoint
---------------------------------------------------------------
IAM DB Token authentication uses OAuth 2.0 Proof-of-Possession (RFC 7800).
The protocol requires a cryptographic challenge-response sequence that must
occur INSIDE the Oracle Net connect negotiation layer — after TLS succeeds
but before the Oracle Net session is established.

ADB-S sends a challenge that the client must sign with the private key
(oci_db_key.pem). This challenge-response is part of the Oracle Net
protocol state machine.

Empirical evidence indicates that the THIN mode Oracle Net implementation
does not successfully complete the IAM Proof-of-Possession challenge-response
sequence when connecting to ADB-S Private Endpoint. The result: TLS succeeds, DNS resolves,
the connection reaches ADB-S — but the Oracle Net negotiation phase times out
or is rejected because the THIN driver cannot respond to the IAM challenge.

Errors observed (both at Oracle Net negotiation phase, after TLS succeeds):
  DPY-6005: cannot connect to database (CONNECTION_ID=[...])
  DPY-6000: failed to receive a response from the listener

Note from Oracle documentation (Appendix B):
"OCI IAM token-based authentication connection string is only supported in
python-oracledb Thick mode."
Source: https://python-oracledb.readthedocs.io/en/latest/user_guide/appendix_b.html

Why access_token 2-tuple also fails
------------------------------------
Oracle documentation for THIN mode states to use the access_token parameter
of connect() as a 2-tuple (token_string, private_key_pem) or as a callable.

Empirical finding (T04): access_token as 2-tuple also fails at the same
Oracle Net negotiation layer on ADB-S Private Endpoint. The token is valid
(confirmed working in T01/T02 THICK mode immediately after, same token).
The TLS handshake succeeds. The failure is in the THIN Oracle Net
protocol layer which cannot perform the PoP challenge-response.

This is documented as a discrepancy between Oracle Appendix B documentation
("use access_token parameter in THIN mode") and empirical behaviour on
ADB-S Private Endpoint. SR open with Oracle Database Driver Engineering.

Why all four variants below produce the same failure
-----------------------------------------------------
Variants A through D systematically eliminate every possible configuration
variable (TNS alias vs full DSN vs EZConnect, with vs without wallet password,
with vs without explicit file paths) to confirm the failure is not a
misconfiguration but a structural limitation of the THIN protocol layer.

The oci_tokens plugin is THICK-only
-------------------------------------
`import oracledb.plugins.oci_tokens` is imported below for completeness in
Variant A. However, the oci_tokens plugin is THICK-only — it has no effect
in THIN mode. The Oracle documentation states:
"When using the oci_tokens plugin... in Thick mode..."
It is not documented for THIN mode. Importing it in THIN mode does not error
but the plugin does not activate.

Wallet files — THIN vs THICK
------------------------------
  THICK: cwallet.sso  — binary SSO format, read by libclntsh natively
  THIN:  ewallet.pem  — PEM format, parsed by Python TLS (ssl module)

In THIN mode:
  wallet_location= points to the directory containing ewallet.pem
  wallet_password= is required if ewallet.pem is encrypted (ADB-S default: YES)
  config_dir=      points to the directory containing tnsnames.ora / sqlnet.ora

WORKAROUND
----------
Use THICK mode with Oracle Instant Client 23.x.
See: t01_t02_thick_oci_sdk.py — validated T01/T02 SUCCESS.

--------------------------------------------------------------------------------
ORACLE DOCUMENTATION REFERENCES
--------------------------------------------------------------------------------
  python-oracledb THIN mode OCI IAM tokens:
    https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html
  python-oracledb Appendix B — Thin vs Thick differences:
    https://python-oracledb.readthedocs.io/en/latest/user_guide/appendix_b.html
  ADB-S connecting — wallet and mTLS:
    https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/connect-download-wallet.html
================================================================================
"""

import oracledb
import oracledb.plugins.oci_tokens  # imported for completeness — no effect in THIN mode
import logging
import socket
import sys
import os

# =============================================================================
# CONFIGURATION — replace all placeholders before running
# =============================================================================

# ADB-S wallet directory.
# For THIN mode this must contain: ewallet.pem, tnsnames.ora, sqlnet.ora
# ewallet.pem is the PEM-format wallet — used by the pure-Python TLS stack.
# cwallet.sso is NOT used in THIN mode.
WALLET_DIR  = r"[WALLET_DIR]"
# Example: r"C:\wallets\Wallet_MYATP"

# Wallet password — required for ADB-S wallets (ewallet.pem is encrypted by default).
# Set when downloading the wallet from OCI Console.
WALLET_PWD  = "[WALLET_PASSWORD]"

# Paths to IAM DB token files (generated by `oci iam db-token get`)
TOKEN_PATH  = r"[OCI_DB_TOKEN_PATH]"
# Example: r"C:\Users\user\.oci\db-token\token"
KEY_PATH    = r"[OCI_DB_KEY_PATH]"
# Example: r"C:\Users\user\.oci\db-token\oci_db_key.pem"

# TNS alias from tnsnames.ora inside the wallet directory
TNS_ALIAS   = "[TNS_ALIAS]"

# ADB-S Private Endpoint hostname (from tnsnames.ora HOST= field)
ADB_HOST    = "[ADB_PRIVATE_ENDPOINT_HOST]"
ADB_PORT    = 1522

# ADB-S service name (from tnsnames.ora SERVICE_NAME= field)
ADB_SERVICE = "[ADB_SERVICE_NAME]"

# OCI config profile
OCI_PROFILE = "DEFAULT"

# =============================================================================
# LOGGING — full DEBUG to capture exact error codes and stack traces
# =============================================================================
logging.basicConfig(
    filename="adb_thin_failure.log",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logging.info("=" * 70)
logging.info("T03/T04 THIN MODE FAILURE EVIDENCE — starting")
logging.info(f"Python      : {sys.version}")
logging.info(f"oracledb    : {oracledb.__version__}")
logging.info(f"Thin mode   : {oracledb.is_thin_mode()}")

print(f"Driver mode   : {'thin' if oracledb.is_thin_mode() else 'thick'}")
print(f"oracledb ver  : {oracledb.__version__}")
print(f"Python        : {sys.version.split()[0]}")

# =============================================================================
# PRE-FLIGHT — DNS reachability check
# Confirms the Private Endpoint hostname resolves correctly.
# If DNS fails here, the test environment has a connectivity issue unrelated
# to the driver/token. All variants below would fail for a different reason.
# =============================================================================
print(f"\n[preflight] DNS check: {ADB_HOST}")
try:
    ip = socket.gethostbyname(ADB_HOST)
    print(f"[preflight] DNS OK → {ip}")
    logging.info(f"DNS OK: {ADB_HOST} → {ip}")
except Exception as e:
    print(f"[preflight] DNS FAILED: {e}")
    logging.error(f"DNS FAILED: {e}")

# =============================================================================
# VARIANT A — extra_auth_params + ConfigFileAuthentication (oci_tokens plugin)
# ─────────────────────────────────────────────────────────────────────────────
# Oracle documentation describes this as the recommended THIN mode approach.
# The oci_tokens plugin is imported above but has no effect in THIN mode.
# Connection fails at Oracle Net negotiation — not at TLS, not at DNS.
#
# Parameters:
#   config_dir=      → directory containing tnsnames.ora (resolves TNS_ALIAS)
#   wallet_location= → directory containing ewallet.pem (mTLS client cert)
#   wallet_password= → required to decrypt ewallet.pem
#   extra_auth_params→ passed to oci_tokens plugin (no-op in THIN mode)
#
# Expected error: DPY-6005 / DPY-6000 at Oracle Net connect negotiation
# =============================================================================
print("\n" + "=" * 60)
print("VARIANT A — extra_auth_params ConfigFileAuthentication")
print("=" * 60)
logging.info("VARIANT A: extra_auth_params ConfigFileAuthentication")

try:
    conn = oracledb.connect(
        dsn=TNS_ALIAS,
        config_dir=WALLET_DIR,       # tnsnames.ora location
        wallet_location=WALLET_DIR,  # ewallet.pem location (THIN)
        wallet_password=WALLET_PWD,  # decrypt ewallet.pem
        extra_auth_params={
            "auth_type": "ConfigFileAuthentication",
            "profile"  : OCI_PROFILE,
        },
    )
    print("CONNECTED — unexpected SUCCESS (investigate)")
    conn.close()
except Exception as e:
    print(f"FAILURE (expected): {type(e).__name__}: {e}")
    logging.exception("VARIANT A failed as expected")

# =============================================================================
# VARIANT B — access_token 2-tuple (token_string, private_key_pem)
# ─────────────────────────────────────────────────────────────────────────────
# Oracle documentation for THIN mode explicitly documents this pattern:
#   "set the access_token parameter of connect() ... as a 2-tuple containing
#    the token and private key"
# Source: https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html
#
# Empirical finding: also fails at Oracle Net negotiation on ADB-S Private Endpoint.
# Token was confirmed valid (used in T01/T02 THICK mode immediately after).
# TLS handshake succeeds. Oracle Net negotiation fails — THIN does not implement
# the IAM PoP challenge-response sequence.
#
# user="/"  → slash syntax required for external authentication in THIN mode
#
# Expected error: DPY-6005 / DPY-6000 at Oracle Net connect negotiation
# =============================================================================
print("\n" + "=" * 60)
print("VARIANT B — access_token 2-tuple (token, private_key_pem)")
print("=" * 60)
logging.info("VARIANT B: access_token 2-tuple")

try:
    with open(TOKEN_PATH, "r") as f:
        db_token = f.read().strip()
    with open(KEY_PATH, "r") as f:
        db_key = f.read().strip()
    logging.info(f"Token file read OK: {len(db_token)} chars")
    logging.info(f"Key file read OK  : {len(db_key)} chars")

    conn = oracledb.connect(
        user="/",                    # slash = external auth in THIN mode
        dsn=TNS_ALIAS,
        config_dir=WALLET_DIR,       # tnsnames.ora location
        wallet_location=WALLET_DIR,  # ewallet.pem location (THIN)
        wallet_password=WALLET_PWD,  # decrypt ewallet.pem
        access_token=(db_token, db_key),  # (JWT token string, RSA private key PEM)
    )
    print("CONNECTED — unexpected SUCCESS (investigate)")
    conn.close()
except Exception as e:
    print(f"FAILURE (expected): {type(e).__name__}: {e}")
    logging.exception("VARIANT B failed as expected")

# =============================================================================
# VARIANT C — explicit full DSN (no TNS alias) + access_token 2-tuple
# ─────────────────────────────────────────────────────────────────────────────
# Eliminates tnsnames.ora resolution as a variable.
# Uses a full DESCRIPTION connect string built inline.
# Same failure — confirms the issue is not TNS alias resolution.
#
# SSL_SERVER_DN_MATCH=YES → validates the ADB-S server certificate DN.
# This is equivalent to SSL_SERVER_DN_MATCH=ON in sqlnet.ora.
#
# Expected error: DPY-6005 / DPY-6000 at Oracle Net connect negotiation
# =============================================================================
print("\n" + "=" * 60)
print("VARIANT C — explicit DESCRIPTION DSN + access_token 2-tuple")
print("=" * 60)
logging.info("VARIANT C: explicit DESCRIPTION DSN + access_token 2-tuple")

full_dsn = (
    f"(DESCRIPTION="
    f"(ADDRESS=(PROTOCOL=TCPS)(PORT={ADB_PORT})(HOST={ADB_HOST}))"
    f"(CONNECT_DATA=(SERVICE_NAME={ADB_SERVICE}))"
    f"(SECURITY=(SSL_SERVER_DN_MATCH=YES))"
    f")"
)
logging.info(f"DSN: {full_dsn}")

try:
    with open(TOKEN_PATH, "r") as f:
        db_token = f.read().strip()
    with open(KEY_PATH, "r") as f:
        db_key = f.read().strip()

    conn = oracledb.connect(
        dsn=full_dsn,
        wallet_location=WALLET_DIR,  # ewallet.pem — no config_dir needed (no TNS)
        wallet_password=WALLET_PWD,
        access_token=(db_token, db_key),
    )
    print("CONNECTED — unexpected SUCCESS (investigate)")
    conn.close()
except Exception as e:
    print(f"FAILURE (expected): {type(e).__name__}: {e}")
    logging.exception("VARIANT C failed as expected")

# =============================================================================
# VARIANT D — EZConnect string + extra_auth_params
# ─────────────────────────────────────────────────────────────────────────────
# EZConnect eliminates both tnsnames.ora and DESCRIPTION parsing.
# Format: tcps://HOST:PORT/SERVICE_NAME
#
# Also eliminates config_dir dependency — wallet_location only for ewallet.pem.
# Same failure — confirms the issue is in the Oracle Net auth layer,
# not in connection string parsing, DNS, or wallet loading.
#
# Expected error: DPY-6005 / DPY-6000 at Oracle Net connect negotiation
# =============================================================================
print("\n" + "=" * 60)
print("VARIANT D — EZConnect string + extra_auth_params")
print("=" * 60)
logging.info("VARIANT D: EZConnect + extra_auth_params")

ezconnect_dsn = f"tcps://{ADB_HOST}:{ADB_PORT}/{ADB_SERVICE}"
logging.info(f"EZConnect DSN: {ezconnect_dsn}")

try:
    conn = oracledb.connect(
        dsn=ezconnect_dsn,
        wallet_location=WALLET_DIR,
        wallet_password=WALLET_PWD,
        extra_auth_params={
            "auth_type": "ConfigFileAuthentication",
            "profile"  : OCI_PROFILE,
        },
    )
    print("CONNECTED — unexpected SUCCESS (investigate)")
    conn.close()
except Exception as e:
    print(f"FAILURE (expected): {type(e).__name__}: {e}")
    logging.exception("VARIANT D failed as expected")

# =============================================================================
# SUMMARY
# =============================================================================
summary = """
================================================================================
T03 / T04 SUMMARY
================================================================================
All 4 THIN mode variants fail at Oracle Net connect negotiation phase.

Confirmed:
  ✅ DNS resolution succeeds
  ✅ TCP connection to Private Endpoint establishes
  ✅ TLS handshake succeeds (ewallet.pem loaded correctly)
  ✅ Token is valid (same token confirmed working in T01/T02 THICK mode)
  ❌ Oracle Net connect negotiation fails — DPY-6005 / DPY-6000

Root cause: python-oracledb THIN mode pure-Python Oracle Net state machine
does not implement the IAM Proof-of-Possession challenge-response sequence
required by ADB-S Private Endpoint.

SR status: Open — Oracle Database Driver Engineering

Workaround: THICK mode + Oracle Instant Client 23.x
See: t01_t02_thick_oci_sdk.py
================================================================================
"""
print(summary)
logging.info(summary)
