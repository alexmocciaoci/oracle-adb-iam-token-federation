# Oracle ADB-S IAM Token Federation — Validation Matrix

> **Empirical validation of OCI IAM DB Token authentication against Oracle Autonomous Database Shared (ADB-S).**
> 23 controlled test scenarios across Python, Java, SQL Developer Classic, SQL Developer VSCode, SQL*Plus, and OCI CLI.
> Human (interactive SSO) and M2M (machine-to-machine) flows — THICK and THIN driver modes — corporate NTLM proxy topology — Private Endpoint — mTLS.
>
> All findings are supported by Oracle Support SR evidence and Oracle Engineering Bug / Enhancement Request acknowledgements.

---

## Why This Repository Exists

OCI IAM DB Token authentication is documented by Oracle at the feature level. What is **not** documented is the systematic behaviour across the full matrix of:

- Driver mode: **THICK** (Oracle Instant Client 19.x / 23.x) vs **THIN** (pure Python / pure Java)
- Token acquisition: **OCI CLI file** vs **OCI SDK in-process** vs **OCI_INTERACTIVE browser SSO**
- Network topology: **Direct** vs **Corporate NTLM Proxy**
- Actor type: **Human** (interactive SSO) vs **M2M** (machine-to-machine automation)
- Tool stack: **Python**, **Java ojdbc17**, **SQL Developer Classic**, **SQL Developer VSCode**, **SQL*Plus**

This repository documents 23 empirical test scenarios with root-cause analysis, Oracle Support SR evidence, and confirmed Bug / Enhancement Request IDs from Oracle Engineering.

Full technical whitepaper: [`docs/whitepaper.pdf`](docs/whitepaper.pdf)
Security architecture deep dive: [`docs/security-architecture.md`](docs/security-architecture.md)
Complete test matrix with SR and Bug tracking: [`matrix/ADB_IAM_Token_Validation_Matrix.xlsx`](matrix/ADB_IAM_Token_Validation_Matrix.xlsx)

---

## Key Findings

**Finding 1 — Python THIN mode: structural failure at Oracle Net connect negotiation (T3 / T4)**
`python-oracledb` 3.4.2 THIN mode fails IAM token authentication post-TLS, during Oracle Net connect negotiation — on both documented injection methods: `access_token` 2-tuple and `access_token` callable via OCI SDK plugin. Token is valid. TLS handshake succeeds. SR open with Oracle Database Driver Engineering.
Workaround: **THICK mode** via `oracledb.init_oracle_client()` + Oracle Instant Client 23.x (T1/T2 — SUCCESS).

**Finding 2 — OCI_INTERACTIVE THICK mode: browser never launched in libclntsh / oci.dll (T8 / T9 / T10 / T11)**
`TOKEN_AUTH=OCI_INTERACTIVE` in `sqlnet.ora` / `tnsnames.ora` tested on two Instant Client versions on SR Engineering request:
- IC 19.29 → `ORA-01017` — feature absent in 19.x, parameter silently ignored
- IC 23.26 → `ORA-25714` — feature present, parameter parsed, but browser never launched

Identical failure from SQL Developer Classic (T8) and SQL*Plus standalone (T10) — confirms the bug is in `libclntsh` / `oci.dll`, not in SQL Developer. SR open with Oracle Client Engineering.

**Finding 3 — SQL Developer VSCode: OCI_INTERACTIVE provider not implemented (T7)**
`ORA-18726: Failed to get a value from an OracleResourceProvider` — the `ojdbc-provider-oci` module is not bundled in the VSCode extension classpath. Failure at `AccessTokenProvider` init, before any network activity. **Code Bug confirmed by Oracle Engineering.**
Workaround: SQL Developer Classic with full `ojdbc-extensions` dependency stack (T18 — SUCCESS without proxy).

**Finding 4 — Corporate NTLM proxy blocks OCI_INTERACTIVE JDBC flow (T14 / T15 / T17)**
The OCI Java SDK (`ApacheConnectorProvider`) does not configure NTLM proxy credentials when `proxyUser` / `proxyPassword` are null — logs: *"Either username or password is null. Not configuring auth credentials for the proxy."* Outbound HTTPS to OCI IAM fails with HTTP 407. **Two Enhancement Requests filed and confirmed by Oracle Engineering.**
Workaround: OCI CLI file token with `HTTPS_PROXY` env var (T16 — SUCCESS).

**Finding 5 — Java M2M ProcessBuilder pattern: separation of proxy concerns (T19 / T20)**
Token acquisition (OCI CLI subprocess + `HTTPS_PROXY`) and JDBC connection (ADB-S Private Endpoint via VCN) have independent network paths and independent proxy requirements. Separating them is the architectural key to M2M in corporate NTLM environments. **Fully validated in production.**

---

## Repository Structure

```
oracle-adb-iam-token-federation/
│
├── python/
│   ├── t01_t02_thick_oci_sdk.py           # T1/T2  — THICK + OCI SDK oci_tokens plugin    [SUCCESS]
│   └── t03_t04_thin_failure.py            # T3/T4  — THIN mode — SR evidence              [FAILURE]
│   └── requirements.txt
│
├── java/
│   └── src/main/java/com/alemoccia/iam/
│       ├── T19_T20_JdbcThinCliToken.java  # T19/T20 — JDBC THIN + OCI CLI ProcessBuilder  [SUCCESS]
│       ├── T21_JdbcThinSdkInProcess.java  # T21    — JDBC THIN + OCI SDK in-process        [WIP]
│       ├── T22_UcpTokenSupplier.java      # T22    — UCP Pool + token supplier             [WIP]
│       └── T23_JdbcThickInstantClient.java# T23    — JDBC THICK + Instant Client           [WIP]
│   └── pom.xml
│
├── matrix/
│   └── ADB_IAM_Token_Validation_Matrix.xlsx
│
├── docs/
│   ├── whitepaper.pdf
│   └── security-architecture.md          # Security model: IAM policies, PoP, mTLS, MFA 26ai, M2M principals
│
└── README.md
```

---

## Validated Production Patterns

### Python — THICK + OCI SDK `oci_tokens` plugin (T1 / T2)

```python
import os, oracledb
import oracledb.plugins.oci_tokens  # registers OCI cloud-native auth plugin

# THICK mode — must call before any connect() or create_pool()
oracledb.init_oracle_client(lib_dir=r"[INSTANT_CLIENT_DIR]")

# cwallet.sso required for THICK mode (ewallet.pem for THIN)
os.environ["TNS_ADMIN"] = r"[WALLET_DIR]"

# In-process token acquisition — no CLI subprocess, no file polling
conn = oracledb.connect(
    dsn="[TNS_ALIAS]",
    externalauth=True,
    extra_auth_params={
        "auth_type": "ConfigFileAuthentication",
        "profile": "DEFAULT",
    },
)
```

### Java — JDBC THIN + OCI CLI ProcessBuilder (T19 / T20)

```java
// Phase A — Token acquisition: OCI CLI handles proxy independently
ProcessBuilder pb = new ProcessBuilder("oci", "iam", "db-token", "get");
pb.environment().put("HTTPS_PROXY", "http://[PROXY_HOST]:[PROXY_PORT]");
pb.start().waitFor(60, TimeUnit.SECONDS);

// Phase B — JDBC connection: direct to ADB-S Private Endpoint via VCN, no proxy
Properties props = new Properties();
props.setProperty(OracleConnection.CONNECTION_PROPERTY_TOKEN_AUTHENTICATION, "OCI_TOKEN");
props.setProperty(OracleConnection.CONNECTION_PROPERTY_TOKEN_LOCATION, "[OCI_DB_TOKEN_DIR]");
// ojdbc17 reads token + oci_db_key.pem and performs PoP signing automatically
```

---

## ADB-S Server Prerequisites

```sql
-- Enable OCI IAM external authentication (one-time, ADMIN privilege)
EXEC DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION(type => 'OCI_IAM', force => TRUE);

-- Map OCI IAM user to a global database schema
CREATE USER [db_schema] IDENTIFIED GLOBALLY AS 'IAM_PRINCIPAL_NAME=[oci_iam_username]';
GRANT CREATE SESSION TO [db_schema];
```

## Token Generation

```bash
# Direct
oci iam db-token get

# Through corporate NTLM proxy
set HTTPS_PROXY=http://[PROXY_HOST]:[PROXY_PORT]
oci iam db-token get

# Output: ~/.oci/db-token/token + ~/.oci/db-token/oci_db_key.pem  (1h TTL)
```

---

## Oracle Support SR and Bug Summary

| Tests | Topic | Status |
|-------|-------|--------|
| T3, T4 | Python THIN — connect negotiation failure | SR open — Oracle Driver Engineering |
| T7, T8, T9, T10, T11 | OCI_INTERACTIVE THICK + VSCode provider | SR open — Oracle Client Engineering |
| T14, T15 | NTLM proxy blocks OCI_INTERACTIVE JDBC | SR closed — Enhancement Requests confirmed |
| T17 | NTLM proxy seamless flow failure | SR closed |

Full SR numbers, Bug IDs, and engineering classification in `matrix/ADB_IAM_Token_Validation_Matrix.xlsx`.

---

## References

- [IAM Token Authentication — ADB-S](https://docs.oracle.com/en-us/iaas/autonomous-database/doc/iam-token-authentication.html)
- [Security Architecture — IAM Policies, PoP, mTLS, MFA 26ai, M2M Principals](docs/security-architecture.md)
- [python-oracledb Authentication Methods](https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html)
- [python-oracledb Appendix B — Thin vs Thick Differences](https://python-oracledb.readthedocs.io/en/latest/user_guide/appendix_b.html)
- [JDBC Client-Side Security — Token-Based Authentication](https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html)
- [oracle-db-examples — JDBC ConnectionSamples](https://github.com/oracle-samples/oracle-db-examples/tree/main/java/jdbc/ConnectionSamples)
- [ojdbc-extensions — ojdbc-provider-oci README](https://github.com/oracle/ojdbc-extensions/blob/main/ojdbc-provider-oci/README.md)
- [Oracle Blog — Accessing ADB with IAM Token using Java](https://blogs.oracle.com/developers/accessing-autonomous-database-with-iam-token-using-java)
- [A-Team — Seamless auth to Oracle DB with SQLDeveloper 23ai](https://www.ateam-oracle.com/seamless-authentication-to-the-oracle-database-with-sqldeveloper-23ai-jdbc-drivers-and-an-oci-identity-domain)
- [OCI CLI — iam db-token get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/db-token/get.html)
- [OCI Java SDK — HttpProxyExample](https://github.com/oracle/oci-java-sdk/blob/master/bmc-examples/src/main/java/HttpProxyExample.java)

---

*Alessandro Moccia — Oracle Solution Architect | OCI Specialist | Oracle ACE Program*
*All findings empirically validated. SR and Bug references in `matrix/ADB_IAM_Token_Validation_Matrix.xlsx`.*
