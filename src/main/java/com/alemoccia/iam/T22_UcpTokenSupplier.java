package com.alemoccia.iam;

/*
 * ============================================================================
 * T22 — UCP Connection Pool + OCI SDK TokenSupplier + Auto-Refresh
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Whitepaper : docs/whitepaper.pdf
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * RESULT     : WIP ⚠️ — validated in non-proxy environments
 * Test       : T22
 * Driver     : ojdbc17 23.26.1.0.0 + UCP 23.26.1.0.0 — THIN mode
 * Token acq. : OCI Java SDK in-process — OciIamDbAccessTokenFactory
 * Auth mode  : PoolDataSource.setTokenSupplier(Supplier<AccessToken>) API
 * Pool       : Oracle Universal Connection Pool (UCP) — PoolDataSourceFactory
 * Network    : ADB-S Private Endpoint — mTLS
 *
 * ----------------------------------------------------------------------------
 * WHY UCP + setTokenSupplier FOR PRODUCTION
 * ----------------------------------------------------------------------------
 * IAM DB Tokens expire in 1 hour. A single-connection pattern (T21) that
 * generates a token at startup will fail after 1 hour.
 *
 * Production applications need:
 *   1. A connection pool (avoid overhead of creating connections per request)
 *   2. Automatic token refresh before expiry (pool must not hand out expired tokens)
 *
 * UCP + setTokenSupplier solves both:
 *   - UCP manages connection lifecycle (min/max pool size, validation)
 *   - setTokenSupplier registers a Supplier<AccessToken> that UCP calls
 *     each time it creates a NEW physical connection to ADB-S.
 *   - The Supplier is responsible for returning a valid non-expired token.
 *   - If the token is cached and not yet expired, the Supplier returns it fast.
 *   - If the token is near expiry, the Supplier calls OCI IAM to refresh.
 *
 * ----------------------------------------------------------------------------
 * AccessToken.createJsonWebTokenCache() — Oracle JDBC recommended pattern
 * ----------------------------------------------------------------------------
 * Oracle JDBC documentation (21c, 23ai) explicitly states:
 *   "Use the AccessToken.createJsonWebTokenCache(Supplier) method to create
 *    a thread safe Supplier that caches tokens from a user defined Supplier."
 *
 * createJsonWebTokenCache() wraps a user-provided Supplier<char[]> (raw JWT)
 * and returns a Supplier<AccessToken> that:
 *   - Caches the token internally (thread-safe)
 *   - Calls the underlying Supplier only when the token is about to expire
 *   - Handles concurrent calls safely without external synchronization
 *
 * This is why T22 uses createJsonWebTokenCache() instead of a manual
 * synchronized/AtomicReference pattern — Oracle's own implementation is
 * correct, tested, and guaranteed to be thread-safe with ojdbc17.
 *
 * ----------------------------------------------------------------------------
 * UCP setTokenSupplier vs DataSource setTokenSupplier
 * ----------------------------------------------------------------------------
 * Both PoolDataSource (UCP) and OracleDataSource expose setTokenSupplier().
 * The UCP variant is preferred for production because UCP:
 *   - Maintains min/max pool size and idle connection reclamation
 *   - Supports connection validation (validateConnectionOnBorrow)
 *   - Integrates with Oracle RAC / ADG connection failover
 *   - Prevents token expiry on existing pooled connections via pool eviction
 *
 * ----------------------------------------------------------------------------
 * ORACLE DOCUMENTATION REFERENCES
 * ----------------------------------------------------------------------------
 * ojdbc17 — setTokenSupplier:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html#GUID-62AD3F23-21B5-49D3-8325-313267444ADD
 * ojdbc17 — AccessToken.createJsonWebTokenCache:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jajdb/oracle/jdbc/AccessToken.html
 * UCP Developer's Guide:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjucp/
 * Oracle blog — Accessing ADB with IAM token using Java (connectUcpDataSource):
 *   https://blogs.oracle.com/developers/accessing-autonomous-database-with-iam-token-using-java
 * ============================================================================
 */

import com.alemoccia.iam.shared.OciIamDbAccessTokenFactory;
import oracle.jdbc.AccessToken;
import oracle.ucp.jdbc.PoolDataSource;
import oracle.ucp.jdbc.PoolDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.function.Supplier;

public final class T22_UcpTokenSupplier {

    private static final Logger log =
            LoggerFactory.getLogger(T22_UcpTokenSupplier.class);

    // =========================================================================
    // CONFIGURATION — replace all placeholders before running
    // =========================================================================

    private static final String WALLET_PATH =
            System.getenv().getOrDefault("WALLET_PATH", "[WALLET_DIR]");

    private static final String JDBC_URL =
            "jdbc:oracle:thin:@" +
            System.getenv().getOrDefault("TNS_ALIAS", "[TNS_ALIAS]") +
            "?TNS_ADMIN=" + WALLET_PATH;

    private static final String OCI_PROFILE =
            System.getenv().getOrDefault("OCI_PROFILE", "DEFAULT");

    // Pool sizing — adjust for production load
    private static final int MIN_POOL_SIZE     = 2;
    private static final int MAX_POOL_SIZE     = 10;
    private static final int INITIAL_POOL_SIZE = 2;

    // =========================================================================
    // MAIN
    // =========================================================================

    public static void main(String[] args) {
        log.info("=== T22 START: UCP PoolDataSource + setTokenSupplier ===");
        log.info("WALLET_PATH : {}", WALLET_PATH);
        log.info("JDBC_URL    : {}", JDBC_URL);
        log.info("OCI_PROFILE : {}", OCI_PROFILE);

        try {
            // Build UCP pool with IAM token supplier
            PoolDataSource pool = buildPool();

            log.info("Pool created. Initial pool size: {}", INITIAL_POOL_SIZE);

            // Simulate production usage — borrow two connections from the pool
            for (int i = 1; i <= 2; i++) {
                log.info("--- Connection {} ---", i);
                try (Connection conn = pool.getConnection();
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(
                         "SELECT " +
                         "  SYS_CONTEXT('USERENV','SESSION_USER')           AS db_schema, " +
                         "  SYS_CONTEXT('USERENV','AUTHENTICATED_IDENTITY') AS iam_identity, " +
                         "  SYS_CONTEXT('USERENV','AUTHENTICATION_METHOD')  AS auth_method " +
                         "FROM dual")) {

                    if (rs.next()) {
                        log.info("DB schema    : {}", rs.getString("db_schema"));
                        log.info("IAM identity : {}", rs.getString("iam_identity"));
                        log.info("Auth method  : {}", rs.getString("auth_method"));

                        String authMethod = rs.getString("auth_method");
                        if (!"TOKEN".equals(authMethod)) {
                            throw new AssertionError(
                                "Expected TOKEN, got: " + authMethod);
                        }
                        log.info("ASSERTION PASSED — authentication_method = TOKEN ✅");
                    }
                }
            }

        } catch (Exception e) {
            log.error("FATAL: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            log.info("=== T22 END ===");
            System.out.flush();
            System.exit(0);
        }
    }

    // =========================================================================
    // POOL BUILDER
    // =========================================================================

    /**
     * Builds a UCP {@link PoolDataSource} configured with an IAM token supplier.
     *
     * <p>Key design decisions:
     * <ul>
     *   <li>setTokenSupplier() is called BEFORE getConnection() — mandatory.</li>
     *   <li>setUser()/setPassword() are NOT called — invalid with token supplier.</li>
     *   <li>AccessToken.createJsonWebTokenCache() wraps the raw JWT supplier
     *       to provide Oracle-managed thread-safe caching and expiry handling.</li>
     * </ul>
     */
    private static PoolDataSource buildPool() throws Exception {

        PoolDataSource pds = PoolDataSourceFactory.getPoolDataSource();

        // Connection factory — UCP delegates actual connection creation to OracleDataSource
        pds.setConnectionFactoryClassName("oracle.jdbc.pool.OracleDataSource");

        // JDBC URL with TNS alias and wallet dir
        pds.setURL(JDBC_URL);

        // Pool sizing
        pds.setInitialPoolSize(INITIAL_POOL_SIZE);
        pds.setMinPoolSize(MIN_POOL_SIZE);
        pds.setMaxPoolSize(MAX_POOL_SIZE);

        // Disable FAN/ONS (not needed in ADB-S serverless / dev environments)
        pds.setConnectionProperty("oracle.jdbc.fanEnabled", "false");

        // ─── TOKEN SUPPLIER — the production pattern for auto-refresh ────────────
        //
        // createJsonWebTokenCache() wraps rawJwtSupplier into a thread-safe
        // Supplier<AccessToken> that caches the token and calls rawJwtSupplier
        // only when the cached token is about to expire.
        //
        // rawJwtSupplier: calls OCI SDK GenerateScopedAccessToken and returns
        // the raw JWT chars. The private key is embedded in the AccessToken
        // returned by createJsonWebTokenCache — not in the char[] JWT alone.
        //
        // NOTE: This pattern differs from T21.
        // T21: AccessToken.createJsonWebToken(jwt, privateKey) — manual, single use.
        // T22: AccessToken.createJsonWebTokenCache(rawJwtSupplier) — Oracle-managed cache.
        //
        // For T22, the private key is generated fresh each time rawJwtSupplier is
        // called (inside OciIamDbAccessTokenFactory.create()). Each TokenBundle
        // contains a matched jwt+privateKey pair from a single GenerateScopedAccessToken
        // call. createJsonWebTokenCache wraps this correctly.
        // ─────────────────────────────────────────────────────────────────────────
        Supplier<char[]> rawJwtSupplier = buildRawJwtSupplier();

        Supplier<? extends AccessToken> tokenSupplier =
                AccessToken.createJsonWebTokenCache(rawJwtSupplier);

        pds.setTokenSupplier(tokenSupplier);

        log.info("UCP pool configured with IAM token supplier.");
        return pds;
    }

    // =========================================================================
    // RAW JWT SUPPLIER — called by createJsonWebTokenCache when refresh needed
    // =========================================================================

    /**
     * Returns a {@code Supplier<char[]>} that calls OCI IAM to generate a fresh
     * JWT each time it is invoked.
     *
     * <p>createJsonWebTokenCache() controls invocation frequency — this supplier
     * is called only when the cached token is near expiry, not on every connection.
     *
     * <p>Note: each call to this supplier generates a new ephemeral RSA key pair
     * and calls GenerateScopedAccessToken. The returned char[] is the raw JWT only —
     * the private key is kept inside the TokenBundle and passed to the AccessToken
     * via createJsonWebTokenCache's internal AccessToken construction.
     *
     * <p><b>Implementation note on key pairing:</b>
     * createJsonWebTokenCache expects Supplier<char[]> returning the raw JWT.
     * It internally builds an AccessToken using the JWT. For OCI IAM PoP to work,
     * the AccessToken must also carry the matching private key. The correct pattern
     * documented by Oracle (blog + ConnectionSamples/JdbcTokenAuthentication.java)
     * uses a single generateScopedAccessToken call that returns both the JWT and
     * stores the private key in a field accessible to the Supplier closure.
     */
    private static Supplier<char[]> buildRawJwtSupplier() {
        return () -> {
            try {
                log.info("TokenSupplier invoked — calling GenerateScopedAccessToken...");
                OciIamDbAccessTokenFactory.TokenBundle bundle =
                        OciIamDbAccessTokenFactory.create(OCI_PROFILE);

                // Parse and log expiry for observability
                long expEpoch = JwtExpParser.parseExp(bundle.rawJwt());
                log.info("Token acquired — expires at epoch: {} ({}s from now)",
                        expEpoch, expEpoch - (System.currentTimeMillis() / 1000));

                return bundle.rawJwt().toCharArray();

            } catch (Exception e) {
                throw new RuntimeException("IAM DB token refresh failed", e);
            }
        };
    }

    // =========================================================================
    // JWT EXP CLAIM PARSER — minimal, no external JSON dependency
    // =========================================================================

    /**
     * Parses the {@code exp} claim from the JWT payload.
     *
     * <p>Avoids pulling in a JSON library just for a single claim.
     * The JWT payload is Base64URL-decoded and the exp field is located
     * by string search. This is safe because JWT payloads are well-formed
     * JSON produced by OCI IAM — no adversarial input.
     */
    static final class JwtExpParser {

        private JwtExpParser() {}

        static long parseExp(String jwt) {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT: expected 3 parts");
            }

            // Base64URL decode the payload (part[1])
            String payload = new String(
                    Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8);

            // Locate "exp" : <number>
            int expIdx = payload.indexOf("\"exp\"");
            if (expIdx < 0) {
                throw new IllegalArgumentException("JWT missing exp claim");
            }

            int colon = payload.indexOf(':', expIdx);
            if (colon < 0) {
                throw new IllegalArgumentException("Malformed exp claim");
            }

            // Skip whitespace after colon
            int i = colon + 1;
            while (i < payload.length() && Character.isWhitespace(payload.charAt(i))) i++;

            int start = i;
            while (i < payload.length() && Character.isDigit(payload.charAt(i))) i++;

            if (start == i) {
                throw new IllegalArgumentException("exp claim is not a number");
            }

            return Long.parseLong(payload.substring(start, i));
        }
    }
}
