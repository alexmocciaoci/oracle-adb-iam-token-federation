package com.alemoccia.iam;

/*
 * ============================================================================
 * T19 / T20 — JDBC THIN + OCI CLI ProcessBuilder — ADB-S mTLS + IAM DB Token
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Whitepaper : docs/whitepaper.pdf
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * RESULT     : SUCCESS ✅
 * Tests      : T19 (no proxy) / T20 (corporate NTLM proxy)
 * Driver     : ojdbc17 23.26.1.0.0 — THIN mode (pure Java, no Instant Client)
 * Token acq. : OCI CLI subprocess (ProcessBuilder) — writes token + key to disk
 * Auth mode  : CONNECTION_PROPERTY_TOKEN_AUTHENTICATION = OCI_TOKEN
 * Network    : ADB-S Private Endpoint — mTLS (ewallet.pem via TNS_ADMIN)
 *
 * ----------------------------------------------------------------------------
 * WHY TWO NETWORK PATHS — the architectural key to T20 (corporate proxy)
 * ----------------------------------------------------------------------------
 *
 * Phase A — IAM plane (token acquisition):
 *   Java process → ProcessBuilder("oci iam db-token get")
 *   OCI CLI uses HTTPS to reach OCI IAM public endpoints.
 *   In corporate NTLM proxy environments: HTTPS_PROXY env var is injected into
 *   the subprocess environment ONLY — not into the JVM system properties.
 *   This completely isolates proxy configuration from the JDBC layer.
 *
 * Phase B — DB plane (database connection):
 *   ojdbc17 THIN → Oracle Net / mTLS → ADB-S Private Endpoint (VCN)
 *   The Private Endpoint is NOT reachable from the public internet.
 *   It is on the OCI VCN internal network — no proxy traversal.
 *   ojdbc17 does NOT go through the corporate proxy for Oracle Net connections.
 *
 * This separation is the architectural key validated in T19/T20. Without it,
 * corporate NTLM proxy environments block OCI CLI HTTPS calls at the JVM level.
 * ProcessBuilder subprocess isolation resolves the conflict completely.
 *
 * ----------------------------------------------------------------------------
 * TOKEN FILES WRITTEN BY OCI CLI
 * ----------------------------------------------------------------------------
 * $HOME/.oci/db-token/token         — JWT signed by OCI IAM (1h TTL)
 * $HOME/.oci/db-token/oci_db_key.pem — Ephemeral RSA private key (PoP key)
 *
 * ojdbc17 reads both files when CONNECTION_PROPERTY_TOKEN_LOCATION is set.
 * It performs the Proof-of-Possession challenge-response automatically.
 * The application never handles the JWT or the private key directly.
 *
 * ----------------------------------------------------------------------------
 * CONNECTION PROPERTIES
 * ----------------------------------------------------------------------------
 * CONNECTION_PROPERTY_TOKEN_AUTHENTICATION = OCI_TOKEN
 *   → JDBC reads token + oci_db_key.pem from TOKEN_LOCATION directory.
 *   → Performs PoP signing with oci_db_key.pem at Oracle Net auth phase.
 *
 * CONNECTION_PROPERTY_TOKEN_LOCATION = TOKEN_DIR
 *   → Overrides default $HOME/.oci/db-token/ location.
 *   → Must be a directory containing exactly: token + oci_db_key.pem
 *
 * oracle.net.tns_admin = WALLET_PATH
 *   → Points Oracle Net to wallet directory containing:
 *     ewallet.pem (mTLS client cert + private key + ADB-S CA root)
 *     tnsnames.ora (TNS alias → HOST/PORT/SERVICE_NAME)
 *     sqlnet.ora (SSL_SERVER_DN_MATCH=ON)
 *
 * oracle.jdbc.fanEnabled = false
 *   → Disables Fast Application Notification (FAN). FAN requires ONS daemon
 *     which is not present in typical dev environments. Without this,
 *     Maven/CLI runs may hang on JVM exit waiting for ONS background threads.
 *
 * ----------------------------------------------------------------------------
 * ORACLE DOCUMENTATION REFERENCES
 * ----------------------------------------------------------------------------
 * JDBC token auth — CONNECTION_PROPERTY_TOKEN_AUTHENTICATION:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html#GUID-62AD3F23-21B5-49D3-8325-313267444ADD
 * OCI CLI db-token get:
 *   https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/db-token/get.html
 * OCI Java SDK proxy example:
 *   https://github.com/oracle/oci-java-sdk/blob/master/bmc-examples/src/main/java/HttpProxyExample.java
 * ============================================================================
 */

import oracle.jdbc.OracleConnection;
import oracle.jdbc.pool.OracleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public final class T19_T20_JdbcThinCliToken {

    private static final Logger log =
            LoggerFactory.getLogger(T19_T20_JdbcThinCliToken.class);

    // =========================================================================
    // CONFIGURATION — replace all placeholders before running
    // =========================================================================

    // Full path to ADB-S wallet directory.
    // Must contain: ewallet.pem, tnsnames.ora, sqlnet.ora
    // Download from OCI Console → ADB-S → Database Connection → Download Wallet
    private static final String WALLET_PATH =
            System.getenv().getOrDefault("WALLET_PATH", "[WALLET_DIR]");
    // Example: "C:/wallets/Wallet_MYATP"  or  "/home/user/wallets/Wallet_MYATP"

    // Directory where OCI CLI writes: token + oci_db_key.pem
    // Default is $HOME/.oci/db-token/ — override only if needed
    private static final String TOKEN_DIR =
            System.getenv().getOrDefault("OCI_DB_TOKEN_DIR",
                    System.getProperty("user.home") + "/.oci/db-token");

    // JDBC URL with TNS alias. TNS_ADMIN in query string → wallet dir for Net layer.
    // Format: jdbc:oracle:thin:@<tns_alias>?TNS_ADMIN=<wallet_path>
    private static final String JDBC_URL =
            "jdbc:oracle:thin:@" +
            System.getenv().getOrDefault("TNS_ALIAS", "[TNS_ALIAS]") +
            "?TNS_ADMIN=" + WALLET_PATH;
    // TNS_ALIAS example: "myatp_high"

    // Optional corporate NTLM proxy.
    // Set USE_PROXY=true and HTTPS_PROXY=http://HOST:PORT in environment.
    // Injected into OCI CLI subprocess env only — NOT into JVM system properties.
    private static final boolean USE_PROXY =
            Boolean.parseBoolean(System.getenv().getOrDefault("USE_PROXY", "false"));
    private static final String HTTPS_PROXY =
            System.getenv().getOrDefault("HTTPS_PROXY", "");

    // =========================================================================
    // MAIN
    // =========================================================================

    public static void main(String[] args) {
        log.info("=== T19/T20 START: OCI CLI ProcessBuilder + JDBC OCI_TOKEN ===");
        log.info("WALLET_PATH : {}", WALLET_PATH);
        log.info("TOKEN_DIR   : {}", TOKEN_DIR);
        log.info("JDBC_URL    : {}", JDBC_URL);
        log.info("USE_PROXY   : {}", USE_PROXY);

        try {
            // Phase A: token acquisition via OCI CLI subprocess
            acquireTokenViaCli();

            // Phase B: JDBC connection using token from disk
            connectAndVerify();

        } catch (Exception e) {
            log.error("FATAL: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            // oracle.jdbc.fanEnabled=false prevents hang here.
            // Without it, background ONS threads keep the JVM alive.
            log.info("=== T19/T20 END ===");
            System.out.flush();
            System.exit(0);
        }
    }

    // =========================================================================
    // PHASE A — Token acquisition via OCI CLI subprocess
    // =========================================================================

    /**
     * Runs {@code oci iam db-token get} as a subprocess.
     *
     * <p>Key design: HTTPS_PROXY is set in the subprocess environment only.
     * This prevents the proxy from interfering with the JDBC Oracle Net
     * connection in Phase B, which must NOT go through any HTTP proxy.
     *
     * <p>The OCI CLI writes two files to TOKEN_DIR:
     * <ul>
     *   <li>{@code token}          — JWT signed by OCI IAM (1h TTL)</li>
     *   <li>{@code oci_db_key.pem} — Ephemeral RSA private key (Proof-of-Possession)</li>
     * </ul>
     */
    private static void acquireTokenViaCli() throws Exception {
        log.info("[Phase A] Running: oci iam db-token get");

        ProcessBuilder pb = new ProcessBuilder("oci", "iam", "db-token", "get");
        pb.redirectErrorStream(false);

        // Inject proxy into subprocess env ONLY — not into JVM system properties.
        // This is the architectural separation that makes T20 work.
        if (USE_PROXY && !HTTPS_PROXY.isBlank()) {
            Map<String, String> env = pb.environment();
            env.put("HTTPS_PROXY", HTTPS_PROXY);
            env.put("HTTP_PROXY",  HTTPS_PROXY);
            log.info("[Phase A] Proxy injected into subprocess: {}", HTTPS_PROXY);
        }

        Process process = pb.start();

        // Drain stderr to prevent subprocess blocking on full pipe buffer
        String stderr = new String(process.getErrorStream().readAllBytes());

        boolean finished = process.waitFor(60, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException(
                "OCI CLI timed out after 60 seconds. " +
                "Check OCI config and network connectivity.");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            log.error("[Phase A] OCI CLI stderr: {}", stderr);
            throw new RuntimeException(
                "OCI CLI exited with code " + exitCode +
                ". See stderr above for details.");
        }

        // Validate token file was actually written / updated
        Path tokenFile = Paths.get(TOKEN_DIR, "token");
        Path keyFile   = Paths.get(TOKEN_DIR, "oci_db_key.pem");

        if (!Files.exists(tokenFile)) {
            throw new RuntimeException(
                "Token file not found after CLI: " + tokenFile +
                ". Check OCI CLI config in ~/.oci/config");
        }
        if (!Files.exists(keyFile)) {
            throw new RuntimeException(
                "Private key file not found after CLI: " + keyFile);
        }

        Instant lastModified = Files.readAttributes(tokenFile,
                BasicFileAttributes.class).lastModifiedTime().toInstant();
        long ageSec = Duration.between(lastModified, Instant.now()).getSeconds();

        log.info("[Phase A] Token file: {} bytes, age: {}s", Files.size(tokenFile), ageSec);
        log.info("[Phase A] Key file  : {} bytes", Files.size(keyFile));

        // Sanity check: if file age > 60s the CLI may have returned a cached token
        // that was not refreshed — warn but do not fail
        if (ageSec > 60) {
            log.warn("[Phase A] Token file age {}s > 60s — CLI may have returned " +
                     "a cached token. Force refresh if needed.", ageSec);
        }

        log.info("[Phase A] Token acquired successfully.");
    }

    // =========================================================================
    // PHASE B — JDBC connection using token from disk
    // =========================================================================

    /**
     * Connects to ADB-S using the token written by the OCI CLI.
     *
     * <p>ojdbc17 reads {@code token} and {@code oci_db_key.pem} from
     * {@code TOKEN_DIR} and performs Proof-of-Possession signing automatically.
     * No username, no password — pure IAM token authentication.
     *
     * <p>The Oracle Net connection goes directly to the ADB-S Private Endpoint
     * via the OCI VCN — no HTTP proxy involved.
     */
    private static void connectAndVerify() throws Exception {
        log.info("[Phase B] Connecting to ADB-S: {}", JDBC_URL);

        OracleDataSource ods = new OracleDataSource();
        ods.setURL(JDBC_URL);

        Properties props = new Properties();

        // --- TOKEN AUTHENTICATION ---
        // OCI_TOKEN: driver reads token + oci_db_key.pem from TOKEN_LOCATION dir.
        // PoP challenge-response is performed automatically by ojdbc17.
        props.setProperty(
            OracleConnection.CONNECTION_PROPERTY_TOKEN_AUTHENTICATION, "OCI_TOKEN");

        // Directory containing: token + oci_db_key.pem
        // Overrides default $HOME/.oci/db-token/
        props.setProperty(
            OracleConnection.CONNECTION_PROPERTY_TOKEN_LOCATION, TOKEN_DIR);

        // --- WALLET / mTLS ---
        // Points Oracle Net to ewallet.pem, tnsnames.ora, sqlnet.ora
        props.setProperty("oracle.net.tns_admin", WALLET_PATH);

        // Server DN match — validates ADB-S server certificate against tnsnames.ora
        props.setProperty("oracle.net.ssl_server_dn_match", "true");

        // --- THREADING ---
        // Disables FAN/ONS background threads that prevent JVM exit in CLI runs.
        // Leave enabled (remove this line) in long-running server applications.
        props.setProperty("oracle.jdbc.fanEnabled", "false");

        // --- NO USERNAME / PASSWORD ---
        // Explicitly null to prevent accidental basic auth fallback.
        ods.setUser(null);
        ods.setPassword(null);

        ods.setConnectionProperties(props);

        try (Connection conn = ods.getConnection()) {
            log.info("[Phase B] === CONNECTED ===");

            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT " +
                     "  SYS_CONTEXT('USERENV','SESSION_USER')           AS db_schema, " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATED_IDENTITY') AS iam_identity, " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATION_METHOD')  AS auth_method " +
                     "FROM dual")) {

                if (rs.next()) {
                    log.info("[Phase B] DB schema       : {}", rs.getString("db_schema"));
                    log.info("[Phase B] IAM identity    : {}", rs.getString("iam_identity"));
                    log.info("[Phase B] Auth method     : {}", rs.getString("auth_method"));

                    // Hard assertion — if this fails, token auth fell back to password
                    String authMethod = rs.getString("auth_method");
                    if (!"TOKEN".equals(authMethod)) {
                        throw new AssertionError(
                            "Expected authentication_method=TOKEN, got: " + authMethod);
                    }
                    log.info("[Phase B] ASSERTION PASSED — authentication_method = TOKEN ✅");
                }
            }
        }

        log.info("[Phase B] Connection closed cleanly.");
    }
}
