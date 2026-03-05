package com.alemoccia.iam;

/*
 * ============================================================================
 * T23 — JDBC OCI driver (THICK) + Oracle Instant Client + IAM DB Token
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Whitepaper : docs/whitepaper.pdf
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * RESULT     : WIP ⚠️
 * Test       : T23
 * Driver     : ojdbc17 23.26.1.0.0 — OCI driver (THICK) via Oracle Instant Client 23.x
 * Auth mode  : OracleConnectionBuilder.accessToken(AccessToken) + JDBC OCI driver
 * Network    : ADB-S Private Endpoint — mTLS (cwallet.sso via TNS_ADMIN)
 *
 * Token acquisition — TWO MODES (switch via USE_CLI_FOR_TOKEN env var):
 *
 *   MODE A — OCI SDK in-process  (USE_CLI_FOR_TOKEN = false, default)
 *     DataplaneClient.generateScopedAccessToken() called from within JVM.
 *     Works without proxy — no-proxy LAN, OCI Compute Instance Principal.
 *     FAILS behind NTLM corporate proxy (Apache HttpClient HTTP 407).
 *     See PROXY LIMITATION section below.
 *
 *   MODE B — OCI CLI ProcessBuilder (USE_CLI_FOR_TOKEN = true)
 *     "oci iam db-token get" run as OS subprocess via ProcessBuilder.
 *     HTTPS_PROXY injected into subprocess env ONLY — not into JVM.
 *     Works in ALL environments including NTLM proxy (same as T19/T20).
 *     Token and key read from TOKEN_DIR/token + TOKEN_DIR/oci_db_key.pem.
 *     AccessToken built in-process from those files.
 *
 * ----------------------------------------------------------------------------
 * WHAT INSTANT CLIENT DOES vs WHAT THE OCI SDK DOES — critical distinction
 * ----------------------------------------------------------------------------
 * Instant Client does NOT generate the IAM token. It knows nothing about OCI IAM.
 *
 * OCI SDK (MODE A) or OCI CLI (MODE B) generates the token:
 *   - Calls OCI IAM GenerateScopedAccessToken API via HTTPS
 *   - Returns JWT signed by OCI IAM + ephemeral RSA private key (PoP key)
 *
 * Oracle Instant Client (libclntsh / oci.dll) handles ONLY the Oracle Net layer:
 *   - Loaded as native C library from java.library.path
 *   - Manages TLS handshake using cwallet.sso (SSO native wallet format)
 *   - Executes Proof-of-Possession challenge-response at Oracle Net auth phase:
 *     ADB-S sends a challenge → libclntsh signs it with the private key inside
 *     the AccessToken → ADB-S verifies with the public key embedded in the JWT
 *   - This is exactly what Python libclntsh does in Python THICK mode (T01/T02)
 *
 * T23 Java THICK is architecturally equivalent to Python T01/T02 THICK:
 *   Python: oracledb.init_oracle_client() → loads libclntsh → oci_tokens plugin
 *   Java:   jdbc:oracle:oci:@ URL prefix  → loads libclntsh → accessToken() API
 *
 * ----------------------------------------------------------------------------
 * TWO NETWORK PHASES
 * ----------------------------------------------------------------------------
 * Phase A — IAM plane (token acquisition, HTTPS to OCI IAM):
 *   MODE A: JVM → DataplaneClient (ApacheHttpClient) → OCI IAM HTTPS endpoint
 *           FAILS in NTLM proxy (ApacheConnectorProvider ignores Authenticator)
 *   MODE B: JVM → ProcessBuilder("oci iam db-token get") → subprocess HTTPS
 *           HTTPS_PROXY in subprocess env only → subprocess reaches OCI IAM
 *           JVM http proxy properties NOT set → JDBC/IC layer completely isolated
 *
 * Phase B — DB plane (Oracle Net to ADB-S Private Endpoint):
 *   BOTH modes identical: libclntsh → Oracle Net mTLS → ADB-S VCN internal
 *   Instant Client does NOT use Java http proxy system properties for Oracle Net.
 *   VCN internal route → no HTTP proxy traversal needed.
 *
 * ----------------------------------------------------------------------------
 * PROXY LIMITATION — Enhancement Requests T14/T15
 * ----------------------------------------------------------------------------
 * In NTLM proxy environments, MODE A fails at Phase A with HTTP 407.
 * Root cause: OCI Java SDK uses Apache HttpClient via ApacheConnectorProvider
 * (Jersey 3). ApacheConnectorProvider reads proxy credentials from Jersey
 * client properties — NOT from java.net.Authenticator.
 * SDK log: "Either username or password is null. Not configuring auth
 * credentials for the proxy." — this is the ApacheConnectorProvider source line.
 * Enhancement Requests confirmed open with Oracle Engineering. No fix ETA.
 * Workaround: set USE_CLI_FOR_TOKEN=true to use MODE B in proxy environments.
 *
 * ----------------------------------------------------------------------------
 * JDBC OCI (THICK) vs JDBC THIN — key differences
 * ----------------------------------------------------------------------------
 * THIN:  jdbc:oracle:thin:@   Pure Java Oracle Net. ewallet.pem. No native libs.
 * OCI:   jdbc:oracle:oci:@    Native libclntsh/oci.dll. cwallet.sso. IC required.
 *
 * The OCI driver auto-loads ocijdbc23.dll (Windows) / libocijdbc23.so (Linux)
 * from java.library.path at the first jdbc:oracle:oci:@ connection.
 * If not found: java.lang.UnsatisfiedLinkError at connection time.
 *
 * ----------------------------------------------------------------------------
 * ORACLE INSTANT CLIENT SETUP
 * ----------------------------------------------------------------------------
 * Download IC 23.x: https://www.oracle.com/database/technologies/instant-client/downloads.html
 *
 *   Windows : set PATH=%PATH%;C:\oracle\instantclient_23_9
 *   Linux   : export LD_LIBRARY_PATH=/opt/oracle/instantclient_23_9
 *   macOS   : export DYLD_LIBRARY_PATH=/opt/oracle/instantclient_23_9
 *   JVM arg : -Djava.library.path=C:\oracle\instantclient_23_9
 *
 * Maven run example:
 *   mvn exec:java -Dexec.mainClass=com.alemoccia.iam.T23_JdbcThickInstantClient \
 *                 -Djava.library.path=C:\oracle\instantclient_23_9
 *
 * ----------------------------------------------------------------------------
 * WALLET — cwallet.sso (THICK) vs ewallet.pem (THIN)
 * ----------------------------------------------------------------------------
 * THICK driver: WALLET_PATH must contain cwallet.sso
 *   cwallet.sso  — Oracle SSO format, read directly by libclntsh
 *   tnsnames.ora — TNS alias resolution
 *   sqlnet.ora   — SSL_SERVER_DN_MATCH=ON, WALLET_LOCATION
 *
 * THIN driver (T19-T22): WALLET_PATH must contain ewallet.pem
 *
 * ADB-S wallet ZIP from OCI Console contains BOTH files — same directory works.
 *
 * ----------------------------------------------------------------------------
 * ORACLE DOCUMENTATION REFERENCES
 * ----------------------------------------------------------------------------
 * JDBC OCI driver:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/23/jjdbc/JDBC-OCI-Driver.html
 * Oracle Instant Client downloads:
 *   https://www.oracle.com/database/technologies/instant-client/downloads.html
 * JDBC IAM token authentication:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html#GUID-62AD3F23-21B5-49D3-8325-313267444ADD
 * cwallet.sso vs ewallet.pem (ADB-S wallet):
 *   https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/adbsb/connect-download-wallet.html
 * OCI CLI db-token get:
 *   https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/db-token/get.html
 * ============================================================================
 */

import com.alemoccia.iam.shared.OciIamDbAccessTokenFactory;
import oracle.jdbc.AccessToken;
import oracle.jdbc.pool.OracleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class T23_JdbcThickInstantClient {

    private static final Logger log =
            LoggerFactory.getLogger(T23_JdbcThickInstantClient.class);

    // =========================================================================
    // CONFIGURATION — replace placeholders or set env vars before running
    // =========================================================================

    // Path to ADB-S wallet directory.
    // THICK mode requires: cwallet.sso + tnsnames.ora + sqlnet.ora
    // (ADB-S wallet ZIP contains both cwallet.sso and ewallet.pem)
    private static final String WALLET_PATH =
            System.getenv().getOrDefault("WALLET_PATH", "[WALLET_DIR]");
    // Example: "C:/wallets/Wallet_MYATP"  or  "/home/user/wallets/Wallet_MYATP"

    // TNS alias from tnsnames.ora inside WALLET_PATH
    private static final String TNS_ALIAS =
            System.getenv().getOrDefault("TNS_ALIAS", "[TNS_ALIAS]");
    // Example: "myatp_high"

    // OCI config profile — used by MODE A (OCI SDK in-process)
    private static final String OCI_PROFILE =
            System.getenv().getOrDefault("OCI_PROFILE", "DEFAULT");

    // Directory where OCI CLI (MODE B) writes: token + oci_db_key.pem
    // Default is $HOME/.oci/db-token/ — same location as T19/T20
    private static final String TOKEN_DIR =
            System.getenv().getOrDefault("OCI_DB_TOKEN_DIR",
                    System.getProperty("user.home") + "/.oci/db-token");

    // =========================================================================
    // MODE SWITCH
    // =========================================================================

    // Controls Phase A — how the IAM DB Token is acquired:
    //
    //   false (default) → MODE A: OCI Java SDK in-process
    //     No proxy:    works perfectly — DataplaneClient calls OCI IAM HTTPS directly
    //     NTLM proxy:  FAILS — ApacheConnectorProvider HTTP 407 (ER T14/T15 open)
    //     Use for:     no-proxy LAN, OCI Compute Instance Principal, CI/CD on OCI
    //
    //   true            → MODE B: OCI CLI subprocess (ProcessBuilder)
    //     NTLM proxy:  works — HTTPS_PROXY injected into subprocess env only
    //     No proxy:    works — subprocess reaches OCI IAM directly
    //     Use for:     corporate NTLM proxy environments
    //     Requires:    OCI CLI installed (oci --version) and configured
    //
    // Set at runtime: USE_CLI_FOR_TOKEN=true mvn exec:java -Dexec.mainClass=...
    private static final boolean USE_CLI_FOR_TOKEN =
            Boolean.parseBoolean(System.getenv().getOrDefault("USE_CLI_FOR_TOKEN", "false"));

    // Proxy settings for MODE B subprocess (same pattern as T19/T20)
    private static final boolean USE_PROXY =
            Boolean.parseBoolean(System.getenv().getOrDefault("USE_PROXY", "false"));
    private static final String HTTPS_PROXY_URL =
            System.getenv().getOrDefault("HTTPS_PROXY", "");

    // JDBC OCI driver URL — jdbc:oracle:oci:@ triggers libclntsh/oci.dll load
    // TNS alias resolved via oracle.net.tns_admin system property (set in main)
    private static final String JDBC_URL = "jdbc:oracle:oci:@" + TNS_ALIAS;

    // =========================================================================
    // MAIN
    // =========================================================================

    public static void main(String[] args) {
        log.info("=== T23 START: JDBC OCI driver (THICK) + Instant Client ===");
        log.info("WALLET_PATH       : {}", WALLET_PATH);
        log.info("TNS_ALIAS         : {}", TNS_ALIAS);
        log.info("JDBC_URL          : {}", JDBC_URL);
        log.info("USE_CLI_FOR_TOKEN : {} ({})",
                USE_CLI_FOR_TOKEN,
                USE_CLI_FOR_TOKEN ? "MODE B — OCI CLI subprocess" : "MODE A — OCI SDK in-process");
        log.info("TOKEN_DIR         : {}", TOKEN_DIR);
        log.info("OCI_PROFILE       : {}", OCI_PROFILE);

        // PRE-FLIGHT — check Instant Client before attempting connection
        checkInstantClientAvailable();

        // Set TNS_ADMIN BEFORE first connection attempt.
        // libclntsh reads cwallet.sso + tnsnames.ora + sqlnet.ora from this path.
        System.setProperty("oracle.net.tns_admin", WALLET_PATH);
        log.info("oracle.net.tns_admin set to: {}", WALLET_PATH);

        try {
            // ── PHASE A — Token acquisition ──────────────────────────────────
            final AccessToken accessToken;

            if (USE_CLI_FOR_TOKEN) {
                // MODE B: OCI CLI subprocess — proxy-safe (same pattern as T19/T20)
                // HTTPS_PROXY in subprocess env only — JVM and libclntsh unaffected
                log.info("[Phase A] MODE B — OCI CLI ProcessBuilder (proxy-safe)");
                acquireTokenViaCli();                    // runs: oci iam db-token get
                accessToken = buildAccessTokenFromFiles(); // reads token + oci_db_key.pem
            } else {
                // MODE A: OCI SDK in-process — no proxy required
                // Works: no-proxy LAN, OCI Compute (Instance/Resource Principal)
                // Fails: NTLM proxy (ApacheConnectorProvider HTTP 407 — ER T14/T15)
                log.info("[Phase A] MODE A — OCI Java SDK in-process (DataplaneClient)");
                OciIamDbAccessTokenFactory.TokenBundle bundle =
                        OciIamDbAccessTokenFactory.create(OCI_PROFILE);
                accessToken = bundle.accessToken();
            }

            log.info("[Phase A] Token acquired successfully.");

            // ── PHASE B — Oracle Net connection via THICK driver (libclntsh) ─
            // Phase B is identical for both MODE A and MODE B.
            // libclntsh uses the private key inside AccessToken for PoP signing.
            log.info("[Phase B] Connecting via jdbc:oracle:oci:@ (THICK / libclntsh)...");
            connectAndVerify(accessToken);

        } catch (Exception e) {
            log.error("FATAL: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            log.info("=== T23 END ===");
            System.out.flush();
            System.exit(0);
        }
    }

    // =========================================================================
    // PHASE A — MODE B: OCI CLI subprocess (proxy-safe)
    // =========================================================================

    /**
     * MODE B — Runs {@code oci iam db-token get} as an OS subprocess.
     *
     * <p>Proxy isolation: {@code HTTPS_PROXY} is set ONLY in the subprocess
     * environment map — not in JVM system properties. This ensures:
     * <ol>
     *   <li>The OCI CLI subprocess can reach OCI IAM through the NTLM proxy.</li>
     *   <li>libclntsh (Phase B) is NOT affected — it uses its own TCP stack
     *       and ignores Java http proxy system properties entirely.</li>
     * </ol>
     *
     * <p>After this method returns, TOKEN_DIR contains:
     * <ul>
     *   <li>{@code token}          — JWT signed by OCI IAM (1h TTL)</li>
     *   <li>{@code oci_db_key.pem} — Ephemeral RSA private key (PKCS#8 PEM)</li>
     * </ul>
     */
    private static void acquireTokenViaCli() throws Exception {
        log.info("[Phase A / MODE B] Running: oci iam db-token get");

        ProcessBuilder pb = new ProcessBuilder("oci", "iam", "db-token", "get");
        pb.redirectErrorStream(false);

        // Inject proxy into subprocess environment ONLY
        // This is the architectural separation that makes MODE B work in NTLM proxy.
        if (USE_PROXY && !HTTPS_PROXY_URL.isBlank()) {
            Map<String, String> env = pb.environment();
            env.put("HTTPS_PROXY", HTTPS_PROXY_URL);
            env.put("HTTP_PROXY",  HTTPS_PROXY_URL);
            log.info("[Phase A / MODE B] Proxy injected into subprocess env: {}", HTTPS_PROXY_URL);
        }

        Process process = pb.start();

        // Drain stderr — prevents subprocess blocking on full pipe buffer
        String stderr = new String(process.getErrorStream().readAllBytes());

        boolean finished = process.waitFor(60, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException(
                "OCI CLI timed out after 60s. Check OCI config and network connectivity.");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            log.error("[Phase A / MODE B] OCI CLI stderr:\n{}", stderr);
            throw new RuntimeException("OCI CLI exited with code " + exitCode);
        }

        // Validate both files are present and recent
        Path tokenFile = Paths.get(TOKEN_DIR, "token");
        Path keyFile   = Paths.get(TOKEN_DIR, "oci_db_key.pem");

        if (!Files.exists(tokenFile)) {
            throw new RuntimeException("token file not found after CLI: " + tokenFile);
        }
        if (!Files.exists(keyFile)) {
            throw new RuntimeException("oci_db_key.pem not found after CLI: " + keyFile);
        }

        Instant lastModified = Files
                .readAttributes(tokenFile, BasicFileAttributes.class)
                .lastModifiedTime().toInstant();
        long ageSec = Duration.between(lastModified, Instant.now()).getSeconds();

        log.info("[Phase A / MODE B] token:         {} bytes, age: {}s", Files.size(tokenFile), ageSec);
        log.info("[Phase A / MODE B] oci_db_key.pem: {} bytes", Files.size(keyFile));

        if (ageSec > 60) {
            log.warn("[Phase A / MODE B] Token file age {}s > 60s — CLI may have returned " +
                     "a cached/unchanged token.", ageSec);
        }
    }

    /**
     * MODE B — Builds an Oracle JDBC {@link AccessToken} from the files
     * written by the OCI CLI ({@code token} + {@code oci_db_key.pem}).
     *
     * <p>This is the in-process equivalent of what ojdbc17 does internally when
     * {@code CONNECTION_PROPERTY_TOKEN_AUTHENTICATION = OCI_TOKEN} is used in T19/T20.
     * Here we build it manually so it can be passed to
     * {@code createConnectionBuilder().accessToken()} with the THICK driver.
     *
     * <p>{@code oci_db_key.pem} is PKCS#8 PEM format — stripped of headers,
     * Base64-decoded to DER, then loaded via {@link KeyFactory}.
     */
    private static AccessToken buildAccessTokenFromFiles() throws Exception {
        Path tokenFile = Paths.get(TOKEN_DIR, "token");
        Path keyFile   = Paths.get(TOKEN_DIR, "oci_db_key.pem");

        // JWT — single UTF-8 line per RFC 7519
        String jwt = Files.readString(tokenFile, StandardCharsets.UTF_8).strip();
        log.info("[Phase A / MODE B] JWT read — length: {} chars", jwt.length());

        // Private key — PKCS#8 PEM → DER → PrivateKey
        String pem = Files.readString(keyFile, StandardCharsets.UTF_8);
        PrivateKey privateKey = parsePkcs8PemPrivateKey(pem);
        log.info("[Phase A / MODE B] Private key loaded from oci_db_key.pem.");

        // Pair JWT + private key into Oracle JDBC AccessToken.
        // libclntsh uses the private key to sign the ADB-S PoP challenge at
        // Oracle Net auth phase (Phase B).
        return AccessToken.createJsonWebToken(jwt.toCharArray(), privateKey);
    }

    /**
     * Parses a PKCS#8 RSA private key from PEM format.
     *
     * <p>OCI CLI writes {@code oci_db_key.pem} in standard PKCS#8 PEM format:
     * {@code -----BEGIN PRIVATE KEY-----} / base64 DER / {@code -----END PRIVATE KEY-----}.
     * No Bouncy Castle needed — standard Java {@link KeyFactory} handles PKCS#8 DER.
     */
    private static PrivateKey parsePkcs8PemPrivateKey(String pem) throws Exception {
        String base64Der = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----",   "")
                .replaceAll("\\s+", "");

        byte[] der = Base64.getDecoder().decode(base64Der);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    // =========================================================================
    // PHASE B — THICK connection via Oracle Instant Client (libclntsh)
    // =========================================================================

    /**
     * Connects to ADB-S via the JDBC OCI driver (THICK mode / libclntsh).
     *
     * <p>Phase B is identical for both MODE A and MODE B — once AccessToken
     * is built, the THICK driver connection logic is the same.
     *
     * <p>libclntsh loads cwallet.sso via Oracle Wallet Manager, manages the
     * mTLS handshake, and performs PoP signing with the private key inside
     * the AccessToken at Oracle Net authentication phase.
     */
    private static void connectAndVerify(AccessToken accessToken) throws Exception {

        OracleDataSource ods = new OracleDataSource();

        // jdbc:oracle:oci:@ — triggers ocijdbc23.dll / libocijdbc23.so load from
        // java.library.path. TNS alias resolved via oracle.net.tns_admin (set in main).
        ods.setURL(JDBC_URL);

        // Pure IAM token authentication — no username, no password.
        // Mixing accessToken() with user/password throws SQLException.
        ods.setUser(null);
        ods.setPassword(null);

        // belt-and-suspenders: also set as system property in main()
        // libclntsh reads cwallet.sso + tnsnames.ora + sqlnet.ora from here
        ods.setConnectionProperty("oracle.net.tns_admin",          WALLET_PATH);
        ods.setConnectionProperty("oracle.net.ssl_server_dn_match", "true");

        // Disable FAN/ONS background threads (prevents JVM hang in CLI runs)
        ods.setConnectionProperty("oracle.jdbc.fanEnabled", "false");

        try (Connection conn = ods.createConnectionBuilder()
                                   .accessToken(accessToken)
                                   .build()) {

            log.info("[Phase B] === CONNECTED via JDBC OCI driver (THICK / libclntsh) ===");

            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT " +
                     "  SYS_CONTEXT('USERENV','SESSION_USER')           AS db_schema,    " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATED_IDENTITY') AS iam_identity, " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATION_METHOD')  AS auth_method,  " +
                     "  SYS_CONTEXT('USERENV','NETWORK_PROTOCOL')       AS net_protocol  " +
                     "FROM dual")) {

                if (rs.next()) {
                    log.info("[Phase B] DB schema    : {}", rs.getString("db_schema"));
                    log.info("[Phase B] IAM identity : {}", rs.getString("iam_identity"));
                    log.info("[Phase B] Auth method  : {}", rs.getString("auth_method"));
                    log.info("[Phase B] Net protocol : {}", rs.getString("net_protocol"));

                    // Hard assertion — TOKEN means IAM auth succeeded via libclntsh PoP
                    String authMethod = rs.getString("auth_method");
                    if (!"TOKEN".equals(authMethod)) {
                        throw new AssertionError(
                            "Expected authentication_method=TOKEN, got: " + authMethod +
                            ". THICK driver may have fallen back to password auth.");
                    }
                    log.info("[Phase B] ASSERTION PASSED — authentication_method = TOKEN ✅");
                }
            }
        }

        log.info("[Phase B] Connection closed cleanly.");
    }

    // =========================================================================
    // PRE-FLIGHT — validate Instant Client before first connection attempt
    // =========================================================================

    /**
     * Pre-flight check for Oracle Instant Client native library on
     * {@code java.library.path}.
     *
     * <p>The JDBC OCI driver loads {@code ocijdbc23.dll} (Windows) or
     * {@code libocijdbc23.so} (Linux/macOS) from {@code java.library.path}
     * at the first {@code jdbc:oracle:oci:@} connection attempt.
     * If missing: {@link UnsatisfiedLinkError} with a cryptic native message.
     *
     * <p>This method logs a clear diagnostic BEFORE that happens.
     * Note: {@code Class.forName("oracle.jdbc.OracleDriver")} validates only
     * classpath (ojdbc17.jar) — it does NOT load the native library.
     * The native lib loads at actual connection time.
     */
    private static void checkInstantClientAvailable() {
        String libPath = System.getProperty("java.library.path", "");
        log.info("[Pre-flight] java.library.path: {}", libPath);

        // Validate ojdbc17.jar is on classpath
        try {
            Class.forName("oracle.jdbc.OracleDriver");
            log.info("[Pre-flight] oracle.jdbc.OracleDriver found on classpath — OK.");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(
                "oracle.jdbc.OracleDriver not on classpath. " +
                "Ensure ojdbc17 is in Maven dependencies.", e);
        }

        // Warn if library path is empty or lacks IC directory
        if (libPath.isBlank()) {
            log.warn("[Pre-flight] java.library.path is EMPTY. " +
                     "THICK driver will fail at connect time with UnsatisfiedLinkError.\n" +
                     "  Windows : set PATH=%PATH%;C:\\oracle\\instantclient_23_9\n" +
                     "  Linux   : export LD_LIBRARY_PATH=/opt/oracle/instantclient_23_9\n" +
                     "  macOS   : export DYLD_LIBRARY_PATH=/opt/oracle/instantclient_23_9\n" +
                     "  JVM arg : -Djava.library.path=C:\\oracle\\instantclient_23_9");
        } else {
            boolean icFound = Arrays.stream(libPath.split("[;:]"))
                    .anyMatch(p -> p.toLowerCase().contains("instantclient") ||
                                  p.toLowerCase().contains("oracle"));
            if (icFound) {
                log.info("[Pre-flight] Instant Client directory detected on java.library.path — OK.");
            } else {
                log.warn("[Pre-flight] java.library.path is set but no 'instantclient' or " +
                         "'oracle' segment found. Verify IC 23.x is included.");
            }
        }
    }
}
