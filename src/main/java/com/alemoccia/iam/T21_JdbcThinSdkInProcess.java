package com.alemoccia.iam;

/*
 * ============================================================================
 * T21 — JDBC THIN + OCI SDK in-process — ADB-S mTLS + IAM DB Token
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Whitepaper : docs/whitepaper.pdf
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * RESULT     : WIP ⚠️ — validated in non-proxy environments
 * Test       : T21
 * Driver     : ojdbc17 23.26.1.0.0 — THIN mode
 * Token acq. : OCI Java SDK in-process — DataplaneClient.generateScopedAccessToken()
 * Auth mode  : OracleConnectionBuilder.accessToken(AccessToken) API
 * Network    : ADB-S Private Endpoint — mTLS
 * Proxy      : NTLM proxy blocks OCI SDK HTTPS call (HTTP 407) — ER T14/T15 open
 *
 * ----------------------------------------------------------------------------
 * ARCHITECTURAL DIFFERENCE vs T19/T20
 * ----------------------------------------------------------------------------
 * T19/T20: Token acquired by OCI CLI subprocess (ProcessBuilder).
 *          HTTPS_PROXY injected into subprocess env only.
 *          JDBC connects independently — no proxy.
 *          Result: works in all environments including NTLM proxy.
 *
 * T21:     Token acquired by OCI Java SDK in-process (DataplaneClient).
 *          GenerateScopedAccessToken is an HTTPS call from the JVM.
 *          In NTLM proxy environments: HTTP 407 — ApacheConnectorProvider
 *          does not use java.net.Authenticator for proxy credentials.
 *          Enhancement Requests T14/T15 confirmed by Oracle Engineering.
 *          Result: validated SUCCESS in no-proxy environments.
 *
 * ----------------------------------------------------------------------------
 * createConnectionBuilder().accessToken() API
 * ----------------------------------------------------------------------------
 * This test uses the OracleConnectionBuilder.accessToken(AccessToken) API —
 * the most direct single-connection pattern.
 *
 * When accessToken() is called on the builder, ojdbc17:
 *   1. Does NOT read token from file system (TOKEN_LOCATION is ignored).
 *   2. Uses the AccessToken object directly for authentication.
 *   3. Performs Proof-of-Possession signing with the private key inside
 *      the AccessToken at Oracle Net authentication phase.
 *
 * This is INCOMPATIBLE with setting a username or password on the same
 * builder. Attempting to set both throws SQLException with invalid config.
 *
 * For connection pooling with auto-refresh, use T22 (UCP + setTokenSupplier).
 *
 * ----------------------------------------------------------------------------
 * ORACLE DOCUMENTATION REFERENCES
 * ----------------------------------------------------------------------------
 * ojdbc17 AccessToken.createJsonWebToken:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html
 * OCI Java SDK DataplaneClient:
 *   https://docs.oracle.com/en-us/iaas/tools/java/latest/com/oracle/bmc/identitydataplane/DataplaneClient.html
 * Oracle blog — Accessing ADB with IAM token using Java:
 *   https://blogs.oracle.com/developers/accessing-autonomous-database-with-iam-token-using-java
 * ============================================================================
 */

import com.alemoccia.iam.shared.OciIamDbAccessTokenFactory;
import oracle.jdbc.AccessToken;
import oracle.jdbc.pool.OracleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public final class T21_JdbcThinSdkInProcess {

    private static final Logger log =
            LoggerFactory.getLogger(T21_JdbcThinSdkInProcess.class);

    // =========================================================================
    // CONFIGURATION — replace all placeholders before running
    // =========================================================================

    // Full path to ADB-S wallet directory.
    // Must contain: ewallet.pem, tnsnames.ora, sqlnet.ora
    private static final String WALLET_PATH =
            System.getenv().getOrDefault("WALLET_PATH", "[WALLET_DIR]");

    // JDBC URL — TNS alias + TNS_ADMIN query parameter
    private static final String JDBC_URL =
            "jdbc:oracle:thin:@" +
            System.getenv().getOrDefault("TNS_ALIAS", "[TNS_ALIAS]") +
            "?TNS_ADMIN=" + WALLET_PATH;

    // OCI config profile in ~/.oci/config
    // Ignored if using Instance/Resource Principal (switch in OciIamDbAccessTokenFactory)
    private static final String OCI_PROFILE =
            System.getenv().getOrDefault("OCI_PROFILE", "DEFAULT");

    // =========================================================================
    // MAIN
    // =========================================================================

    public static void main(String[] args) {
        log.info("=== T21 START: OCI SDK in-process + createConnectionBuilder.accessToken() ===");
        log.info("WALLET_PATH : {}", WALLET_PATH);
        log.info("JDBC_URL    : {}", JDBC_URL);
        log.info("OCI_PROFILE : {}", OCI_PROFILE);

        try {
            // Step 1 — Acquire IAM DB Token via OCI SDK in-process
            // DataplaneClient.generateScopedAccessToken() → JWT + ephemeral private key
            log.info("[Step 1] Calling GenerateScopedAccessToken via OCI Java SDK...");
            OciIamDbAccessTokenFactory.TokenBundle bundle =
                    OciIamDbAccessTokenFactory.create(OCI_PROFILE);
            log.info("[Step 1] Token acquired.");

            // Step 2 — Connect to ADB-S using AccessToken (no username, no password)
            log.info("[Step 2] Connecting via createConnectionBuilder().accessToken()...");
            connectAndVerify(bundle.accessToken());

        } catch (Exception e) {
            log.error("FATAL: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            log.info("=== T21 END ===");
            System.out.flush();
            System.exit(0);
        }
    }

    // =========================================================================
    // CONNECTION
    // =========================================================================

    /**
     * Connects to ADB-S using {@link oracle.jdbc.OracleConnectionBuilder#accessToken}.
     *
     * <p>The AccessToken wraps the JWT and the matching RSA private key.
     * ojdbc17 performs Proof-of-Possession signing automatically at the
     * Oracle Net authentication phase.
     *
     * <p>Important: do NOT set user or password on the DataSource.
     * Setting both accessToken and credentials throws SQLException.
     */
    private static void connectAndVerify(AccessToken accessToken) throws Exception {

        OracleDataSource ods = new OracleDataSource();
        ods.setURL(JDBC_URL);

        // No username, no password — pure IAM token authentication
        ods.setUser(null);
        ods.setPassword(null);

        // Disable FAN/ONS background threads (prevents JVM hang in CLI runs)
        ods.setConnectionProperty("oracle.jdbc.fanEnabled", "false");

        // createConnectionBuilder().accessToken() overrides TOKEN_LOCATION.
        // The driver uses the AccessToken object directly — no file system read.
        try (Connection conn = ods.createConnectionBuilder()
                                   .accessToken(accessToken)
                                   .build()) {

            log.info("[Step 2] === CONNECTED ===");

            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT " +
                     "  SYS_CONTEXT('USERENV','SESSION_USER')           AS db_schema, " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATED_IDENTITY') AS iam_identity, " +
                     "  SYS_CONTEXT('USERENV','AUTHENTICATION_METHOD')  AS auth_method " +
                     "FROM dual")) {

                if (rs.next()) {
                    log.info("[Step 2] DB schema    : {}", rs.getString("db_schema"));
                    log.info("[Step 2] IAM identity : {}", rs.getString("iam_identity"));
                    log.info("[Step 2] Auth method  : {}", rs.getString("auth_method"));

                    String authMethod = rs.getString("auth_method");
                    if (!"TOKEN".equals(authMethod)) {
                        throw new AssertionError(
                            "Expected authentication_method=TOKEN, got: " + authMethod);
                    }
                    log.info("[Step 2] ASSERTION PASSED — authentication_method = TOKEN ✅");
                }
            }
        }
        log.info("[Step 2] Connection closed cleanly.");
    }
}
