"""
================================================================================
T01 / T02 — python-oracledb THICK mode + OCI SDK oci_tokens plugin
================================================================================
Repository  : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
Whitepaper  : docs/whitepaper.pdf
Author      : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program

RESULT      : SUCCESS ✅
Tests       : T01 (Human SSO — oci session token) / T02 (M2M — API Key)
Driver      : python-oracledb 3.4.2 — THICK mode via Oracle Instant Client 23.x
Token acq.  : OCI SDK oci_tokens plugin — in-process, no CLI subprocess
Network     : ADB-S Private Endpoint — mTLS (cwallet.sso)
Proxy       : No proxy

--------------------------------------------------------------------------------
ARCHITECTURE
--------------------------------------------------------------------------------

Why THICK mode is required for the oci_tokens plugin
-----------------------------------------------------
python-oracledb operates in two modes:

  THIN mode  — pure Python implementation of Oracle Net protocol.
               No Instant Client required. Lighter dependency footprint.
               IAM token support via access_token parameter only.
               Does NOT support oci_tokens plugin.

  THICK mode — uses Oracle Instant Client (libclntsh / oci.dll).
               Full Oracle Net protocol stack in native C library.
               Supports oci_tokens plugin + ConfigFileAuthentication.
               PoP (Proof-of-Possession) signing handled by libclntsh.

The oci_tokens plugin is THICK-only. Oracle documentation explicitly states:
"When using the oci_tokens plugin to generate OCI IAM tokens to connect to
Oracle Autonomous Database in Thick mode, you need to explicitly set the
externalauth and extra_auth_params parameters of oracledb.connect()."
Source: https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html

init_oracle_client() — why it must be the first call
------------------------------------------------------
oracledb.init_oracle_client() loads the Instant Client shared libraries
(libclntsh.so on Linux, oci.dll on Windows) into the Python process.
It MUST be called before any connect(), create_pool(), or other driver
operations. Once called, the process is permanently in THICK mode —
there is no way to switch back to THIN in the same process.

If init_oracle_client() is not called, the driver starts in THIN mode by
default and the oci_tokens plugin import will succeed but the plugin will
have no effect — connect() will fail with authentication errors.

The oci_tokens plugin — what it does
--------------------------------------
`import oracledb.plugins.oci_tokens` registers a cloud-native authentication
plugin that integrates the OCI Python SDK into the python-oracledb auth chain.

When connect() is called with extra_auth_params containing auth_type =
"ConfigFileAuthentication", the plugin:
  1. Reads ~/.oci/config (or file_location override) to locate the API Key.
  2. Calls the OCI IAM GenerateScopedAccessToken API using the OCI Python SDK.
  3. Receives the JWT token + ephemeral private key (oci_db_key.pem equivalent).
  4. Passes the token to libclntsh for Proof-of-Possession signing.
  5. libclntsh performs the PoP challenge-response with ADB-S.

The OCI SDK call happens IN-PROCESS — no subprocess, no file polling, no
dependency on oci iam db-token get. Token refresh on expiry is also handled
automatically by the plugin for connection pools.

externalauth=True — why it is mandatory
-----------------------------------------
externalauth=True instructs python-oracledb THICK mode to use Oracle external
authentication — bypassing the standard Oracle username/password auth chain.
Without it, the driver ignores extra_auth_params entirely and attempts
password-based authentication, which fails with ORA-01017.

TNS_ADMIN environment variable
--------------------------------
Setting os.environ["TNS_ADMIN"] tells Oracle Net (libclntsh) where to find:
  - tnsnames.ora  — TNS alias → HOST / PORT / SERVICE_NAME resolution
  - sqlnet.ora    — SSL_SERVER_DN_MATCH=ON, wallet parameters
  - cwallet.sso   — client certificate + private key + ADB-S CA root (mTLS)

For THICK mode, cwallet.sso is the correct wallet file (SSO format, native C).
For THIN mode, ewallet.pem is used instead (PEM format, pure Python TLS).

Verification query — what each SYS_CONTEXT value means
--------------------------------------------------------
  SESSION_USER           → the Oracle DB schema mapped via IDENTIFIED GLOBALLY
  AUTHENTICATED_IDENTITY → the OCI IAM username (email / principal name)
  AUTHENTICATION_METHOD  → must be "TOKEN" — confirms IAM token auth, not password

If AUTHENTICATION_METHOD returns "PASSWORD", the token auth silently fell back
to password authentication — this indicates a configuration error.

--------------------------------------------------------------------------------
ORACLE DOCUMENTATION REFERENCES
--------------------------------------------------------------------------------
  python-oracledb auth methods:
    https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html
  python-oracledb Appendix B (Thin vs Thick differences):
    https://python-oracledb.readthedocs.io/en/latest/user_guide/appendix_b.html
  OCI IAM DB Token — ADB-S:
    https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/manage-users-iam.html
  IAM policy prerequisites:
    https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/iam-create-groups-policies.html
================================================================================
"""

import os
import oracledb

# oci_tokens plugin registration — MUST be imported before init_oracle_client()
# This import registers the OCI SDK-backed authentication provider inside
# python-oracledb's plugin registry. No public symbols are exposed; the side
# effect of the import is the registration itself.
import oracledb.plugins.oci_tokens

# =============================================================================
# CONFIGURATION — replace all placeholders before running
# =============================================================================

# Full path to Oracle Instant Client 23.x directory.
# Must contain: libclntsh.so (Linux) or oci.dll (Windows) and supporting libs.
# Download: https://www.oracle.com/database/technologies/instant-client/downloads.html
# Minimum version for full IAM DB Token PoP support: 23.x (recommended) or 19.14+
INSTANT_CLIENT_DIR = r"[INSTANT_CLIENT_DIR]"
# Linux example : "/opt/oracle/instantclient_23_9"
# Windows example: r"C:\oracle\instantclient_23_9"

# Full path to ADB-S wallet directory.
# For THICK mode this directory must contain: cwallet.sso, tnsnames.ora, sqlnet.ora
# Download wallet from OCI Console → ADB-S → Database Connection → Download Wallet
# Select "Instance Wallet" type for mTLS.
WALLET_DIR = r"[WALLET_DIR]"
# Example: r"C:\wallets\Wallet_MYATP"  or  "/home/user/wallets/Wallet_MYATP"

# TNS alias defined in tnsnames.ora inside the wallet directory.
# Available aliases: [db_name]_high, [db_name]_medium, [db_name]_low, [db_name]_tp, [db_name]_tpurgent
# Choose based on workload concurrency requirements.
TNS_ALIAS = "[TNS_ALIAS]"
# Example: "myatp_high"

# OCI config profile name in ~/.oci/config.
# The profile must contain: tenancy, user, fingerprint, key_file, region.
# For M2M (T02): use the service principal / API Key profile.
# For Human SSO (T01): the oci_tokens plugin uses the active OCI session token
#   if obtained via `oci session authenticate` — no API Key needed for Human users.
OCI_PROFILE = "DEFAULT"

# =============================================================================
# STEP 1 — THICK MODE INITIALISATION
# Must be the first oracledb call in the process.
# After this call, oracledb.is_thin_mode() returns False permanently.
# =============================================================================
oracledb.init_oracle_client(lib_dir=INSTANT_CLIENT_DIR)

print(f"[init] Driver mode  : {'thin' if oracledb.is_thin_mode() else 'thick'}")
print(f"[init] oracledb ver : {oracledb.__version__}")

# =============================================================================
# STEP 2 — WALLET via TNS_ADMIN
# Oracle Net (libclntsh) reads tnsnames.ora, sqlnet.ora, and cwallet.sso
# from the directory pointed to by TNS_ADMIN.
# =============================================================================
os.environ["TNS_ADMIN"] = WALLET_DIR
print(f"[init] TNS_ADMIN    : {WALLET_DIR}")

# =============================================================================
# STEP 3 — TOKEN AUTH PARAMS for the oci_tokens plugin
#
# auth_type = "ConfigFileAuthentication"
#   → instructs the plugin to read ~/.oci/config and use the OCI SDK
#     to call GenerateScopedAccessToken in-process.
#
# profile = OCI_PROFILE
#   → selects the profile section in ~/.oci/config.
#     The profile must point to a valid API Key with tenancy/user/fingerprint.
#
# Optional: "file_location" → override ~/.oci/config path if needed.
# =============================================================================
token_auth_params = {
    "auth_type": "ConfigFileAuthentication",
    "profile"  : OCI_PROFILE,
    # "file_location": r"[OCI_CONFIG_FILE_PATH]",  # optional override
}

# =============================================================================
# STEP 4 — CONNECT
#
# externalauth=True  — mandatory for THICK mode external auth (oci_tokens plugin)
# dsn=TNS_ALIAS      — resolved via tnsnames.ora in WALLET_DIR
# extra_auth_params  — passed to the registered oci_tokens plugin
#
# Under the hood:
#   1. oci_tokens plugin calls OCI IAM GenerateScopedAccessToken
#   2. Plugin passes token + ephemeral key to libclntsh
#   3. libclntsh performs Proof-of-Possession challenge-response with ADB-S
#   4. Oracle Net session established over mTLS (cwallet.sso)
# =============================================================================
print(f"\n[conn] Connecting to {TNS_ALIAS} ...")

conn = oracledb.connect(
    dsn=TNS_ALIAS,
    externalauth=True,        # mandatory — tells THICK mode to use external auth
    extra_auth_params=token_auth_params,
)

print("[conn] Connection established.\n")

# =============================================================================
# STEP 5 — VERIFY IAM TOKEN AUTHENTICATION
#
# AUTHENTICATED_IDENTITY must show the OCI IAM username / principal.
# AUTHENTICATION_METHOD  must be "TOKEN" — not "PASSWORD".
# SESSION_USER           is the Oracle DB schema mapped via IDENTIFIED GLOBALLY.
# =============================================================================
with conn.cursor() as cur:
    cur.execute("""
        SELECT
            SYS_CONTEXT('USERENV', 'SESSION_USER')           AS db_schema,
            SYS_CONTEXT('USERENV', 'AUTHENTICATED_IDENTITY') AS iam_identity,
            SYS_CONTEXT('USERENV', 'AUTHENTICATION_METHOD')  AS auth_method
        FROM dual
    """)
    row = cur.fetchone()

    print("=" * 50)
    print(f"  DB schema       : {row[0]}")
    print(f"  IAM identity    : {row[1]}")
    print(f"  Auth method     : {row[2]}")
    print("=" * 50)

    # Hard assertion — if this fails, token auth silently fell back to password
    assert row[2] == "TOKEN", (
        f"ASSERTION FAILED: expected authentication_method=TOKEN, got {row[2]}. "
        "Check externalauth=True and extra_auth_params configuration."
    )
    print("\n✅ ASSERTION PASSED — authentication_method = TOKEN")

conn.close()
print("[conn] Connection closed cleanly.")
