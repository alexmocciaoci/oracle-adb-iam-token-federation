# OCI IAM DB Token — Security Architecture and Enterprise Deployment Rationale

> **Oracle Autonomous AI Database Serverless (ADB-S 26ai) — Enterprise Security Deep Dive**
>
> Why OCI IAM DB Token with mTLS and Private Endpoint is the gold standard for enterprise workloads with ultra-sensitive data. This document covers: the two-policy IAM prerequisite model, the no-credentials Human SSO architecture, M2M patterns for containers and functions (Instance/Resource Principal), the MFA landscape on ADB-S newly announced for both 19c and 26ai, the cryptographic Proof-of-Possession model, mTLS double-key exchange, and open findings from Oracle Engineering — Bugs, Enhancement Requests, and Oracle Support SRs.
>
> Part of: [`oracle-adb-iam-token-federation`](https://github.com/alexmocciaoci/oracle-adb-iam-token-federation)

---

## 1. Mandatory IAM Policies — Two Policies, Two Resource Types, Both Required

IAM DB Token authentication on ADB-S requires **two independent OCI IAM policies** governing two completely different OCI resource types. Without both, authentication fails with errors that do not clearly identify the missing policy.

> **Oracle documentation states explicitly:**
> *"Defining a policy is required to use IAM tokens to access Autonomous Database. A policy is not required when using IAM database passwords."*
>
> Source: [Create IAM Groups and Policies for IAM Users — Oracle ADB Serverless](https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/iam-create-groups-policies.html)

---

### Policy 1 — `use autonomous-databases` — Authorises IAM DB Token issuance

This policy authorises the IAM group to invoke `GetAutonomousDatabaseConsoleToken` — the OCI IAM API operation that issues the scoped db-token for a specific ADB-S instance. Without this policy, `oci iam db-token get` and `GenerateScopedAccessToken` (OCI SDK) fail with a permissions error before any token is generated.

```hcl
# Standard form — compartment scope
allow group [IAM_GROUP_NAME] to use autonomous-databases in compartment [COMPARTMENT_NAME]

# Least-privilege form — restricts to token issuance operation only (validated via Oracle Support SR)
# No other autonomous-databases operations are granted (start / stop / update / scale / delete)
allow group [IAM_GROUP_NAME] to use autonomous-databases in compartment [COMPARTMENT_NAME]
  WHERE ANY { request.operation = 'GetAutonomousDatabaseConsoleToken' }

# Single ADB-S instance — most restrictive, recommended for production
allow group [IAM_GROUP_NAME] to use autonomous-databases in compartment [COMPARTMENT_NAME]
  WHERE ANY { request.operation = 'GetAutonomousDatabaseConsoleToken',
              target.id = 'ocid1.autonomousdatabase.oc1.[region].[unique_id]' }
```

---

### Policy 2 — `use database-connections in tenancy` — Authorises token retrieval

This policy governs the `database-connections` resource type — a completely distinct OCI resource type from `autonomous-databases`. It **must be written at tenancy level**. Compartment scope does not work for `database-connections`.

```hcl
# MANDATORY: tenancy level — compartment scope is NOT supported for database-connections
allow group [IAM_GROUP_NAME] to use database-connections in tenancy
```

> Source: [Authenticating and Authorizing IAM Users for Oracle DBaaS — Database Security Guide](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/authenticating-and-authorizing-iam-users-oracle-dbaas-databases.html)

---

### Complete working example — both policies together

```hcl
# Policy 1 — token issuance, least privilege, compartment scope
allow group OCI-db-developers to use autonomous-databases in compartment prod-compartment
  WHERE ANY { request.operation = 'GetAutonomousDatabaseConsoleToken' }

# Policy 2 — token retrieval, MANDATORY tenancy level
allow group OCI-db-developers to use database-connections in tenancy
```

---

### M2M — Instance Principal and Resource Principal require a Dynamic Group

Oracle documentation explicitly states: Instance Principal and Resource Principal **cannot be mapped directly to a static IAM group** — they must go through a Dynamic Group.

```hcl
# Dynamic Group — OCI Compute instances in a compartment
All {instance.compartment.id = 'ocid1.compartment.oc1..[compartment_ocid]'}

# Dynamic Group — OCI Functions (serverless)
All {resource.type = 'fnfunc', resource.compartment.id = 'ocid1.compartment.oc1..[id]'}

# Dynamic Group — OKE pods (Resource Principal)
All {resource.type = 'cluster', resource.compartment.id = 'ocid1.compartment.oc1..[id]'}

# Same two policies for Dynamic Groups
allow dynamic-group [DG_NAME] to use autonomous-databases in compartment [COMPARTMENT]
  WHERE ANY { request.operation = 'GetAutonomousDatabaseConsoleToken' }

allow dynamic-group [DG_NAME] to use database-connections in tenancy
```

---

## 2. Why IAM Token Is Architecturally Superior to Static Database Passwords

| Security Property | Static Password | IAM DB Token |
|-------------------|----------------|--------------|
| Credential lifetime | Indefinite | 1 hour — hard TTL, OCI IAM enforced |
| Application storage required | Yes — vault / env / file | No — generated on demand |
| Replay protection | None | OAuth 2.0 Proof-of-Possession — token alone is worthless |
| Identity source | Local DB verifier | OCI IAM — central, auditable, policy-governed |
| MFA for Human users | Requires RADIUS or DBMS_MFA config | Enforced natively by OCI IAM Identity Domain at SSO |
| Credential rotation | Manual, complex | Automatic — every token is a new ephemeral credential |
| Lateral movement risk | High — valid everywhere | Contained — scoped to specific ADB-S service |
| OCI IAM policy governance | None | Mandatory — additional authorisation layer at issuance |

---

## 3. Why 1-Hour TTL Is a Security Control, Not a Limitation

A stolen static password is permanently valid until someone manually revokes it. A stolen IAM DB Token:

- Is valid for **at most 1 hour** from issuance — no matter what.
- **Cannot be used without `oci_db_key.pem`** — the Proof-of-Possession private key never leaves the client (see Section 4).
- Cannot be refreshed without re-authenticating to OCI IAM — MFA required for Human users.

The worst-case scenario: an attacker who exfiltrates both the token file and the private key has a maximum 1-hour window — and only if they can also reach the ADB-S Private Endpoint from inside the OCI VCN. Three independent barriers must fail simultaneously.

For M2M: the application must explicitly call `GenerateScopedAccessToken` every hour — a deliberate, policy-governed, application-logged event, not a silent long-lived credential sitting in memory.

---

## 4. Proof-of-Possession (PoP) — Why Token Replay Is Cryptographically Impossible

OCI IAM DB Token implements **OAuth 2.0 Proof-of-Possession (RFC 7800)**. Token replay is structurally impossible — not a configuration choice.

### What token generation produces

```
~/.oci/db-token/token          ← JWT signed by OCI IAM
                                  Contains: IAM principal identity + embedded CLIENT PUBLIC KEY

~/.oci/db-token/oci_db_key.pem ← Ephemeral RSA private key — generated CLIENT-SIDE
                                  NEVER transmitted to OCI IAM or ADB-S
                                  Required to sign the ADB-S cryptographic challenge
```

### The PoP handshake — what happens at every connection

```
Client driver (libclntsh / ojdbc17 / python-oracledb THICK)         ADB-S
      │                                                                │
      │── presents JWT token ──────────────────────────────────────►  │
      │                                                                │ validates JWT
      │                                                                │ via OCI IAM JWKS
      │◄── cryptographic challenge ────────────────────────────────── │
      │                                                                │
      │    signs challenge with oci_db_key.pem (private key)          │
      │                                                                │
      │── signed challenge response ──────────────────────────────►   │
      │                                                                │ validates PoP using
      │                                                                │ PUBLIC KEY in JWT body
      │◄── Oracle Net session established ───────────────────────────  │
```

An attacker who intercepts the JWT has only the token. Without `oci_db_key.pem` they cannot sign the ADB-S challenge. The connection is rejected unconditionally.

**IAM DB Token is a Proof-of-Possession token — not a Bearer token. Possession of the JWT alone has zero authentication value.**

---

## 5. MFA on Oracle Autonomous AI Database — Full Landscape (New Feature, February 2026)

MFA on ADB-S covers two completely distinct and independent authentication populations. Understanding the separation is critical for enterprise architects.

> **Release note — February 2026:**
> Oracle Autonomous AI Database Serverless now supports native Multifactor Authentication (MFA) for **both 19c and 26ai** database versions.
>
> Source: [ADB Serverless Release Notes — February 2026: Multifactor Authentication](https://docs.oracle.com/en-us/iaas/releasenotes/autonomous-database-serverless/2026-02-multifactor-authentication.htm)
>
> Full feature documentation: [Use Multifactor Authentication with Autonomous AI Database](https://docs.oracle.com/en-us/iaas/autonomous-database-serverless/doc/multifactor-authentication-autonomous-ai-database.html)

---

### 5.1 MFA for IAM-Federated Users (IAM DB Token flow) — enforced by OCI IAM Identity Domain

For users authenticated via OCI IAM (the subject of this entire validation), **MFA is enforced entirely at the OCI IAM Identity Domain level** — before the db-token is ever issued. The database itself does not participate in MFA for these users. No `DBMS_MFA_*` configuration is required or applicable.

The flow:
1. Human user runs `oci iam db-token get` or connects via SQL Developer OCI_INTERACTIVE.
2. OCI IAM presents the browser login page (OCI Console SSO or federated IdP: Azure Entra ID, Okta, Ping, etc.).
3. OCI IAM enforces the **second factor** per Identity Domain MFA policy: TOTP, OMA push notification, Cisco Duo, FIDO2, SMS — configured centrally by the Identity Domain administrator.
4. Only after successful MFA does OCI IAM issue the db-token.

**This is architecturally superior:** MFA protects the credential issuance event itself. Even if the db-token is later stolen, it expires within 1 hour and requires the PoP private key to be used at all.

---

### 5.2 Native MFA on ADB-S for Local Database Users — New Feature February 2026 (19c and 26ai)

Oracle introduced **native MFA for local database users** on ADB-S Serverless in **February 2026**, available for **both 19c and 26ai**. Before this release, adding MFA to local database accounts required an external RADIUS server, OCI IAM federation, or Kerberos integration. From February 2026, MFA can be configured directly via `DBMS_MFA_ADMIN` packages — no external IdP needed.

This is a **fundamentally different authentication path from IAM DB Token**:

| Property | IAM Token flow (this validation) | Native DB MFA (local users) |
|----------|----------------------------------|----------------------------|
| User type | IDENTIFIED GLOBALLY (OCI IAM identity) | IDENTIFIED BY password (local Oracle account) |
| MFA enforced by | OCI IAM Identity Domain | ADB-S DBMS_MFA_ADMIN packages |
| Second factor delivery | OCI IAM (TOTP / OMA / Duo / FIDO2) | OMA push, Cisco Duo push, Email OTP, Slack OTP |
| DB configuration | None required | CONFIGURE_NOTIFICATION + REGISTER_USER |
| Can be combined | SQL Access Token MFA works post-IAM-login | Login MFA or SQL Access Token MFA for password users |

**Two MFA enforcement modes for local users:**

**Mode 1 — Login-Time MFA (`LOGON`):** MFA required at connection time, before the database session is established. The database server sends a push notification to the registered app after password validation. Supported channels: Oracle Mobile Authenticator (OMA), Cisco Duo — push only.

```sql
BEGIN
  DBMS_MFA_ADMIN.REGISTER_USER(
    username   => 'DB_LOCAL_USER',
    type       => 'LOGON',
    email      => 'user@company.com',
    attributes => JSON_OBJECT('auth_method' VALUE 'oma_push')
  );
END;
/
```

**Mode 2 — SQL Access Token MFA:** The user connects with password normally, but must verify via a second factor before executing protected SQL statements. Delivery: OMA (push notification), Email (OTP), Slack (OTP). Applicable also after IAM token login — IAM-authenticated users can be required to present an SQL Access Token before executing sensitive statements.

```sql
BEGIN
  DBMS_MFA_ADMIN.REGISTER_USER(
    username   => 'DB_LOCAL_USER',
    type       => 'SQL ACCESS',
    email      => 'user@company.com',
    attributes => JSON_OBJECT(
      'duration_min'    VALUE 720,
      'scope'           VALUE 'SESSION',
      'read_only'       VALUE TRUE
    )
  );
END;
/
```

**Notification channel matrix:**

| Channel | Login MFA | SQL Access Token MFA | Delivery method |
|---------|-----------|---------------------|-----------------|
| Oracle Mobile Authenticator (OMA) | ✅ | ✅ | Push notification — no OTP generated |
| Cisco Duo | ✅ | ❌ | Push notification |
| Email | Enrollment only | ✅ | OTP delivery |
| Slack | ❌ | ✅ | OTP delivery |

> **Important architectural note:** The SQL Access Token MFA (Mode 2) can be layered **on top** of IAM DB Token authentication. An IAM-federated user who connects with a db-token can still be required to present a SQL Access Token before executing protected statements — providing a fourth factor of verification beyond network (Private Endpoint), transport (mTLS), and authentication (IAM Token + PoP).

---

## 6. The Human SSO Model — Why Users Never Have OCI API Keys

This is the architectural heart of the IAM DB Token Human flow — and the most misunderstood aspect in enterprise deployments.

### The structural separation: Human SSO vs M2M

| Property | Human User (SSO) | M2M Application |
|----------|-----------------|-----------------|
| OCI identity type | IAM user — console access, no API Key | Service principal — API Key / Instance / Resource Principal |
| Has `~/.oci/config` API Key | **NO — by design** | Yes — required for programmatic OCI access |
| Has OCI RSA private key file | NO | Yes |
| Token acquisition method | Browser SSO → OCI session token → db-token | OCI SDK / OCI CLI with API Key or Instance Principal |
| MFA enforcement | OCI IAM Identity Domain — always at browser login | Not applicable — service principal, no interactive session |
| Can bypass MFA | No — browser SSO always enforces IAM Identity Domain policy | N/A — different authentication chain |

### Why Human users must NOT have OCI API Keys

An OCI API Key allows **headless, non-interactive, programmatic** access to OCI IAM. A Human user with an API Key could:

- Call `GenerateScopedAccessToken` from any machine without browser SSO.
- **Bypass the Identity Domain MFA policy entirely** — programmatic API Key authentication does not trigger the MFA step.
- Share the API Key — a static long-lived credential that defeats the entire IAM DB Token security model.

**The correct enterprise design:** Human users authenticate to OCI IAM exclusively via the browser, using `oci session authenticate` which produces a **session token** — derived from the browser SSO with MFA, inheriting its TTL and revocation properties.

```bash
# Human user — one-time session setup (browser + MFA required)
oci session authenticate --profile HUMAN_PROFILE
# → browser opens → OCI IAM login → MFA enforced → session token written

# Token acquisition uses the session — no API Key
oci iam db-token get --auth security_token --profile HUMAN_PROFILE
# → GenerateScopedAccessToken called with session credential
# → ~/.oci/db-token/token + ~/.oci/db-token/oci_db_key.pem written

# Database connection — no username, no password
sqlplus /@my_adb_tns_alias
```

The OCI session expires (configurable in the Identity Domain, typically 8–24 hours). Re-authentication with MFA is required at every session renewal. No persistent access is possible without the second factor.

---

### SQL Developer OCI_INTERACTIVE — Seamless Human SSO via JDBC THIN ojdbc-extensions

For Human users in SQL Developer Classic, the `OCI_INTERACTIVE` authentication mode (`oracle.jdbc.tokenAuthentication=OCI_INTERACTIVE`) automates the entire browser SSO flow inside the IDE, using the **JDBC extensions from `oracle/ojdbc-extensions`** (`ojdbc-provider-oci` module).

This is the seamless pattern documented by the Oracle A-Team: the `ojdbc-provider-oci` provider calls `GenerateScopedAccessToken` via the OCI Java SDK using the active OCI Identity Domain browser session — the user never sees or handles a token file.

```
SQL Developer Classic 24.3.1 (ojdbc17 + ojdbc-provider-oci + oci-java-sdk)
      │── connection request (OCI_INTERACTIVE) ──────────────────► OCI IAM Identity Domain
      │◄── system browser opens automatically ─────────────────────
      │    user: OCI Console login + MFA (OMA / FIDO2 / TOTP)
      │◄── browser: "Authentication complete — return to SQL Developer" ─
      │    token returned in-memory to ojdbc-provider-oci
      │── JDBC connect: token + PoP signing (ojdbc17) ─────────────► ADB-S Private Endpoint
      │◄── Oracle Net session established ────────────────────────────
      │    authentication_method = TOKEN
      │    authenticated_identity = OCI IAM username
      │    session_user = globally identified DB schema
```

**Maven dependency — required to enable OCI_INTERACTIVE in SQL Developer Classic:**

```xml
<dependency>
    <groupId>com.oracle.database.jdbc</groupId>
    <artifactId>ojdbc-provider-oci</artifactId>
    <version>1.0.6</version>
    <!-- Transitively pulls:
         oci-java-sdk-identitydataplane
         oci-java-sdk-shaded-full -->
</dependency>
```

Built JARs added to SQL Developer `product.conf`:
```
AddJavaLibFile /path/to/ojdbc-provider-oci-1.0.6.jar
AddJavaLibFile /path/to/oci-java-sdk-identitydataplane-x.x.x.jar
AddJavaLibFile /path/to/oci-java-sdk-shaded-full-x.x.x.jar
```

Connection Advanced Property: `oracle.jdbc.tokenAuthentication = OCI_INTERACTIVE`

> Reference: [A-Team — Seamless authentication to Oracle DB with SQLDeveloper 23ai and OCI Identity Domain](https://www.ateam-oracle.com/seamless-authentication-to-the-oracle-database-with-sqldeveloper-23ai-jdbc-drivers-and-an-oci-identity-domain)
> Reference: [Oracle Blog — 23ai JDBC Extensions — OCI_INTERACTIVE seamless flow](https://blogs.oracle.com/developers/post/23c-jdbc-extensions-for-oci-iam-azure-ad)

---

### Current Validation Status — OCI_INTERACTIVE and Known Bugs

| Test | Tool | Proxy | Result | Root Cause |
|------|------|-------|--------|-----------|
| T18 | SQL Developer Classic 24.3.1 | No proxy | ✅ **SUCCESS** | Seamless browser flow — globally identified user validated |
| T7  | SQL Developer VSCode 25.3.2  | NTLM proxy | ❌ **Code Bug** | `ORA-18726` — `ojdbc-provider-oci` not bundled in VSCode extension classpath |
| T14 | SQL Developer Classic 24.3.1 | NTLM proxy | ❌ **ER filed** | `HTTP 407` — OCI Java SDK does not configure NTLM credentials |
| T15 | SQL Developer VSCode 25.3.2  | NTLM proxy | ❌ **ER filed** | `HTTP 407` — same SDK root cause |

**T7 Bug — origin and confirmed status:**

The issue was first reported in the Oracle Community Forum thread opened as the starting point for the Oracle Support SR. The forum post documented `ORA-18726` errors when attempting `OCI_INTERACTIVE` in the SQL Developer VSCode extension despite correct `product.conf` configuration. The SR confirmed the root cause: `ojdbc-provider-oci` and its OCI Java SDK dependencies are not bundled in the VSCode extension classpath — unlike SQL Developer Classic. Oracle Engineering has confirmed this as a Code Bug.

> Forum: [Oracle Community — OCI_INTERACTIVE seamless IAM token authentication with SQL Developer 24.3](https://forums.oracle.com/ords/r/apexds/community/q?question=seamless-iam-db-token-authentication-sql-developer)

**T14/T15 ER — root cause:**

`ojdbc-provider-oci` calls the OCI IAM OAuth2 endpoints via `ApacheConnectorProvider` in the OCI Java SDK. When a corporate NTLM proxy is in the path and `proxyUser`/`proxyPassword` are not configured, the SDK logs: *"Either username or password is null. Not configuring auth credentials for the proxy."* The HTTPS call to OCI IAM returns HTTP 407. Enhancement Requests filed with Oracle Engineering.

**Workaround for NTLM proxy environments (T16 — validated SUCCESS):**

```bash
# Step 1 — Token via OCI CLI subprocess with proxy env var (no NTLM issue)
set HTTPS_PROXY=http://[PROXY_HOST]:[PORT]
oci iam db-token get  # → writes token + oci_db_key.pem to ~/.oci/db-token/

# Step 2 — SQL Developer Advanced Connection Properties
oracle.jdbc.tokenAuthentication = OCI_TOKEN
oracle.jdbc.tokenLocation       = C:\Users\[user]\.oci\db-token\
```

---

## 7. M2M Architecture — Instance Principal, Resource Principal, API Key

For M2M workloads (Java applications, Python services, batch jobs, microservices, serverless functions, containers), the application authenticates to OCI IAM using a **service principal** — never a Human identity, never a browser session.

### Pattern A — API Key (`~/.oci/config`) — on-premises and development

```
Application
  → reads ~/.oci/config (tenancy OCID, user OCID, fingerprint, private key path)
  → signs OCI API request with RSA private key
  → calls GenerateScopedAccessToken (OCI SDK or OCI CLI)
  → receives db-token + oci_db_key.pem (1h TTL)
  → connects ADB-S Private Endpoint: mTLS + IAM DB Token + PoP
```

Use case: on-premises servers, developer workstations, CI/CD pipelines. The API Key is a long-lived OCI credential and must be stored securely (OCI Vault, OS keyring, HSM). Validated as T19/T20 SUCCESS in this repository.

### Pattern B — Instance Principal — OCI Compute VM / Bare Metal

```
OCI Compute instance
  → authenticated automatically by OCI hypervisor via IMDS
    (http://169.254.169.254 — internal OCI network, no proxy ever required)
  → Dynamic Group membership links instance to IAM policy
  → GenerateScopedAccessToken called — NO credential file on disk
  → db-token issued scoped to this specific compute instance identity
  → connects ADB-S Private Endpoint via VCN — no proxy
```

Use case: Java / Python applications running directly on OCI Compute. **No credential file. No API Key. No secret to manage, rotate, or leak.** The OCI hypervisor handles authentication transparently.

```java
// Java — Instance Principal
AuthenticationDetailsProvider auth =
    InstancePrincipalsAuthenticationDetailsProvider.builder().build();
DatabaseClient client = DatabaseClient.builder().build(auth);
// GenerateScopedAccessToken → db-token → JDBC connect
```

```python
# Python — Instance Principal
import oci
signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
# IMDS internal — zero proxy, zero credentials file
```

### Pattern C — Resource Principal — OCI Functions / OKE pods / Containers

```
OCI Function invocation / OKE pod / container workload
  → OCI runtime injects ephemeral credential into execution environment
    (env vars: OCI_RESOURCE_PRINCIPAL_VERSION, RPST, OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM)
  → Dynamic Group rule matches resource type: fnfunc / cluster / container-instance
  → GenerateScopedAccessToken called — credential injected by runtime, NEVER on disk
  → db-token issued scoped to this specific function execution / pod lifecycle
  → connects ADB-S Private Endpoint via VCN internal routing
```

Use case: **serverless functions** (OCI Functions), **Kubernetes workloads** (OKE), **container instances**. The credential is injected at runtime by the OCI orchestration layer. The application code contains **zero credential material** — there is nothing to exfiltrate, rotate, or store. Each function invocation or pod restart gets a fresh ephemeral credential from the OCI runtime.

```python
# Python — Resource Principal (OCI Functions, OKE, Container Instances)
import oci
signer = oci.auth.signers.get_resource_principals_signer()
# Runtime-injected env vars → zero credential files → zero secrets in code
```

```java
// Java — Resource Principal
AuthenticationDetailsProvider auth =
    ResourcePrincipalAuthenticationDetailsProvider.builder().build();
```

**This is the most secure M2M pattern for cloud-native architectures.** The attack surface for credential theft is structurally zero: there is no API Key file to steal, no vault secret to exfiltrate, no environment variable to leak beyond the function execution lifetime.

### The proxy separation principle — on-premises M2M in enterprise environments

In corporate NTLM proxy environments, M2M has two completely independent network paths — the architectural insight validated in T19/T20:

```
Path A — IAM plane (token acquisition):
  Application → HTTPS → Corporate NTLM Proxy → OCI IAM public endpoints
  (proxy required — GenerateScopedAccessToken is an HTTPS call to OCI IAM REST API)
  Solution: OCI CLI subprocess with HTTPS_PROXY env var → clean process separation

Path B — DB plane (database connection):
  ojdbc17 / python-oracledb THICK → Oracle Net / mTLS → ADB-S Private Endpoint (VCN)
  NO proxy traversal — Private Endpoint is on the internal OCI VCN network
  ADB-S is not reachable from the public internet regardless of proxy
```

For **Instance Principal / Resource Principal on OCI Compute or OCI Functions**: both paths use the OCI internal network — IMDS is internal, ADB-S Private Endpoint is on the VCN. The corporate proxy is entirely irrelevant. This is an additional operational advantage of cloud-native M2M patterns in enterprise environments.

**Validated production pattern — Java ProcessBuilder (T20):**

```java
// Phase A: OCI CLI subprocess — handles proxy independently via env vars
log.info("IAM DB token refresh starting — principal={} ts={}", principalId, Instant.now());
ProcessBuilder pb = new ProcessBuilder("oci", "iam", "db-token", "get",
    "--profile", ociProfile);
pb.environment().put("HTTPS_PROXY", "http://[PROXY_HOST]:[PORT]");
int exit = pb.start().waitFor(60, TimeUnit.SECONDS);
log.info("IAM DB token refresh complete — exit={} elapsed={}ms", exit, elapsed);

// Phase B: JDBC connects to ADB-S Private Endpoint — VCN direct, no proxy
Properties props = new Properties();
props.setProperty(OracleConnection.CONNECTION_PROPERTY_TOKEN_AUTHENTICATION, "OCI_TOKEN");
props.setProperty(OracleConnection.CONNECTION_PROPERTY_TOKEN_LOCATION, tokenDir);
props.setProperty("oracle.net.tns_admin", walletDir);
Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@" + tnsAlias, props);
```

---

## 8. mTLS — Double-Key Mutual Authentication — Why MITM Is Structurally Impossible

Oracle recommends TLS as the minimum for ADB-S. This validation uses **mTLS** — a transport-layer hardening that is independent of and additive to the IAM DB Token application-layer authentication.

### ADB-S wallet — file by file

| File | Driver | Contents | Purpose |
|------|--------|----------|---------|
| `cwallet.sso` | THICK (libclntsh) | Client cert + client private key + ADB-S CA root | OCI native C library loads natively |
| `ewallet.pem` | THIN (python-oracledb, ojdbc17) | Same in PEM format | Pure-protocol Java and Python drivers parse directly |
| `tnsnames.ora` | All | HOST / PORT / SERVICE_NAME per alias | TNS alias resolution |
| `sqlnet.ora` | All | `SSL_SERVER_DN_MATCH=ON` | Validates ADB-S server certificate Distinguished Name |

### The double-key exchange at TLS handshake

- **The client** has the ADB-S CA root certificate (in wallet). Validates that the ADB-S server certificate is signed by that CA. **ADB-S cannot be impersonated** — a rogue server without a valid CA-signed certificate fails the client TLS handshake.
- **ADB-S** has the client CA root. Validates the client certificate. **A client without a wallet certificate cannot complete the TLS handshake** — the Oracle Net layer is never reached, no Oracle Net protocol data is exchanged.

### Why MITM is structurally impossible with mTLS

A Man-in-the-Middle proxy between client and ADB-S would need simultaneously:
- A certificate trusted by the **client's CA root** — to impersonate ADB-S to the client.
- A certificate trusted by **ADB-S's CA root** — to impersonate the client to ADB-S.

This requires the ADB-S server private key (controlled by Oracle) and the client wallet private key (in `cwallet.sso` / `ewallet.pem`). Both are inaccessible. The MITM cannot complete either TLS handshake — the connection fails at the transport layer.

**With one-way TLS only:** a corporate SSL inspection proxy with its CA installed in the OS trust store intercepts the connection transparently. This is a real, widely deployed attack vector in enterprise environments. mTLS eliminates it structurally: the client must present a wallet certificate, which a proxy cannot forge without the matching private key.

For regulated, financial, or healthcare workloads, mTLS is not an option — it is the minimum required transport security. Oracle provides it on ADB-S; it must be used.

---

## 9. Private Endpoint — Four Independent and Additive Security Layers

| Layer | Mechanism | What it prevents |
|-------|-----------|-----------------|
| 1 — Network | OCI VCN Private Endpoint | All public internet access — not routable, not discoverable |
| 2 — Transport | mTLS — bilateral certificate exchange | MITM, rogue endpoints, clients without wallet |
| 3 — Authentication | IAM DB Token + PoP (RFC 7800) | Replay attacks, stolen token without `oci_db_key.pem` |
| 4 — Authorization | OCI IAM policy + DB global role mapping | Unauthorised token issuance, schema lateral movement |

All four layers are independent. Defeating any one does not help with the others. An attacker who possesses a valid token, the matching private key, and a valid client certificate cannot reach ADB-S from outside the VCN — the network layer alone stops them.

---

## 10. Open SR: GenerateScopedAccessToken Not Tracked in OCI Audit Log

**Security observability gap — Oracle Support SR open and confirmed:**

When `GenerateScopedAccessToken` is called — via `oci iam db-token get` or OCI SDK (Java / Python) — **the event does not appear in the OCI Audit Log** for the tenancy. Token issuance is not auditable via the standard OCI Audit channel.

**Why this matters for enterprise security:** SIEM and compliance teams monitoring OCI Audit Log cannot detect when a db-token was issued, for which IAM principal, for which ADB-S service, or from which IP address. This is a gap in the security observability model.

**Status:** Oracle Support Engineering is investigating in the backend with specialised support. Gap is confirmed by Oracle.

**Enterprise workaround — application-level token issuance logging:**

```java
// Ship these logs to OCI Logging / Splunk / ELK as interim SIEM source
log.info("IAM_DB_TOKEN_REFRESH_START principal={} profile={} ts={} host={}",
    principalId, ociProfile, Instant.now(), InetAddress.getLocalHost().getHostName());
// ... ProcessBuilder: oci iam db-token get (T20 pattern)
log.info("IAM_DB_TOKEN_REFRESH_DONE exit={} elapsed={}ms ts={}",
    exitCode, elapsed, Instant.now());
```

---

## 11. Complete Security Posture — March 2026

| Security Control | Mechanism | Status |
|-----------------|-----------|--------|
| No static DB passwords | IAM DB Token — generated on demand, 1h TTL | ✅ Validated |
| Short-lived credentials | 1h TTL — OCI IAM enforced, no exceptions | ✅ Validated |
| Replay protection | OAuth 2.0 PoP — RFC 7800 — oci_db_key.pem required | ✅ Validated |
| MFA for Human users (IAM) | OCI IAM Identity Domain — browser SSO — no API Key | ✅ Validated T12 / T18 |
| MFA for local DB users | DBMS_MFA_ADMIN — OMA / Duo / Email / Slack | ✅ New — February 2026 ADB-S 19c + 26ai |
| SQL Access Token MFA | DBMS_MFA — layerable on top of IAM Token login | ✅ New — February 2026 |
| Mutual TLS | cwallet.sso + ewallet.pem — bilateral cert exchange | ✅ Validated — all tests |
| MITM prevention | mTLS — double private key required | ✅ Validated |
| Network isolation | ADB-S Private Endpoint — VCN only, not internet-routable | ✅ Validated |
| Policy — token issuance | `use autonomous-databases` + `GetAutonomousDatabaseConsoleToken` | ✅ Validated |
| Policy — token retrieval | `use database-connections in tenancy` (tenancy mandatory) | ✅ Validated |
| Human SSO — no API Key | `oci session authenticate` → session token → db-token | ✅ Architecture validated |
| M2M — Instance Principal | OCI Compute — IMDS internal — no credential on disk | ✅ Architecture documented |
| M2M — Resource Principal | OCI Functions / OKE / Containers — runtime-injected | ✅ Architecture documented |
| OCI_INTERACTIVE no proxy | SQL Developer Classic 24.3.1 — T18 | ✅ SUCCESS |
| OCI_INTERACTIVE NTLM proxy | SQL Developer Classic / VSCode — T7 / T14 / T15 | ❌ Bug + ER — Oracle Engineering |
| File token workaround (NTLM) | OCI CLI + `OCI_TOKEN` mode — T16 | ✅ SUCCESS |
| Token issuance OCI audit | OCI Audit Log — GenerateScopedAccessToken | ⚠️ SR open — gap confirmed |
| Token issuance app audit | Application-level logging — T20 pattern | ✅ Documented and implemented |

---

## 12. References — All Verified March 2026

**Oracle ADB Serverless — IAM Token, MFA, Release Notes**
- [Create IAM Groups and Policies for IAM Users — ADB Serverless](https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/iam-create-groups-policies.html) ✅
- [Use IAM Authentication with ADB Serverless](https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/manage-users-iam.html) ✅
- [Enable IAM Authentication on ADB Serverless](https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/enable-iam-authentication.html) ✅
- [**Use Multifactor Authentication with ADB Serverless — 19c and 26ai**](https://docs.oracle.com/en-us/iaas/autonomous-database-serverless/doc/multifactor-authentication-autonomous-ai-database.html) ✅
- [**ADB Serverless Release Notes — February 2026: MFA**](https://docs.oracle.com/en-us/iaas/releasenotes/autonomous-database-serverless/2026-02-multifactor-authentication.htm) ✅
- [What's New for ADB Serverless](https://docs.oracle.com/en-us/iaas/autonomous-database-serverless/doc/whats-new-adwc.html) ✅

**Oracle Database Security Guide**
- [Authenticating IAM Users for Oracle DBaaS — DB 19c](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/authenticating-and-authorizing-iam-users-oracle-dbaas-databases.html) ✅
- [Authenticating IAM Users for Oracle DBaaS — DB 26 (current)](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/authenticating-and-authorizing-iam-users-oracle-dbaas-databases.html) ✅
- [sqlnet.ora Parameters — TOKEN_AUTH, OCI_INTERACTIVE](https://docs.oracle.com/en/database/oracle/oracle-database/26/netrf/parameters-for-the-sqlnet.ora.html) ✅

**Oracle JDBC**
- [JDBC Client-Side Security — Token-Based Authentication](https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html#GUID-62AD3F23-21B5-49D3-8325-313267444ADD) ✅
- [oracle-db-examples — JDBC ConnectionSamples](https://github.com/oracle-samples/oracle-db-examples/tree/main/java/jdbc/ConnectionSamples) ✅
- [ojdbc-extensions — ojdbc-provider-oci](https://github.com/oracle/ojdbc-extensions/blob/main/ojdbc-provider-oci/README.md) ✅

**python-oracledb**
- [Authentication Methods — OCI IAM section](https://python-oracledb.readthedocs.io/en/stable/user_guide/authentication_methods.html) ✅
- [Appendix B — Thin vs Thick Mode Differences](https://python-oracledb.readthedocs.io/en/latest/user_guide/appendix_b.html) ✅

**Oracle Blogs and A-Team**
- [A-Team — Seamless auth to Oracle DB with SQLDeveloper 23ai and OCI Identity Domain](https://www.ateam-oracle.com/seamless-authentication-to-the-oracle-database-with-sqldeveloper-23ai-jdbc-drivers-and-an-oci-identity-domain) ✅
- [Oracle Blog — 23ai JDBC Extensions — OCI_INTERACTIVE seamless flow](https://blogs.oracle.com/developers/post/23c-jdbc-extensions-for-oci-iam-azure-ad) ✅
- [Oracle Blog — Accessing ADB with IAM Token using Java](https://blogs.oracle.com/developers/accessing-autonomous-database-with-iam-token-using-java) ✅

**OCI SDK and CLI**
- [OCI CLI — iam db-token get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/db-token/get.html) ✅
- [OCI Python SDK — Resource Principals](https://docs.oracle.com/en-us/iaas/tools/python/latest/sdk_behaviors/resource_principals.html) ✅
- [OCI Java SDK — HttpProxyExample](https://github.com/oracle/oci-java-sdk/blob/master/bmc-examples/src/main/java/HttpProxyExample.java) ✅

---

*Alessandro Moccia — Oracle Solution Architect | OCI Specialist | Oracle ACE Program*
*Part of: [oracle-adb-iam-token-federation](https://github.com/alexmocciaoci/oracle-adb-iam-token-federation)*
