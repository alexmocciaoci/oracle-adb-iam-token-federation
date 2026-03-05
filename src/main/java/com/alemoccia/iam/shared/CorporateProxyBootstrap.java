package com.alemoccia.iam.shared;

/*
 * ============================================================================
 * CorporateProxyBootstrap — NTLM Corporate Proxy configuration for OCI SDK
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * PURPOSE
 * -------
 * Configures Java system properties and java.net.Authenticator for NTLM proxy
 * authentication. Used ONLY for Phase A (OCI IAM HTTPS calls via OCI Java SDK).
 *
 * CRITICAL ARCHITECTURAL NOTE
 * ---------------------------
 * This bootstrap applies ONLY to the OCI Java SDK HTTPS calls that reach
 * OCI IAM to call GenerateScopedAccessToken.
 *
 * It does NOT affect Oracle Net / JDBC connections to ADB-S Private Endpoint.
 * Oracle Net (ojdbc17) uses its own TCP stack and ignores JVM http proxy
 * system properties. The ADB-S Private Endpoint is on the VCN internal
 * network and is NOT reachable via HTTP proxy anyway.
 *
 * KNOWN LIMITATION — Enhancement Requests T14/T15
 * ------------------------------------------------
 * The OCI Java SDK uses Apache HttpClient via ApacheConnectorProvider.
 * When NTLM proxy credentials are provided via java.net.Authenticator,
 * the SDK logs: "Either username or password is null. Not configuring
 * auth credentials for the proxy." and the HTTPS call fails with HTTP 407.
 *
 * Root cause: ApacheConnectorProvider reads proxy credentials from Jersey
 * client properties, not from java.net.Authenticator. The Authenticator
 * set here is effective for JDK's built-in HttpURLConnection but NOT for
 * Apache HttpClient used by the OCI SDK.
 *
 * Status: Enhancement Requests filed and confirmed by Oracle Engineering.
 *
 * Workaround: Use OCI CLI subprocess (T19/T20) instead of OCI SDK in-process
 * for proxy environments. See T19_T20_JdbcThinCliToken.java.
 *
 * ENVIRONMENT VARIABLES
 * ---------------------
 * PROXY_HOST   — proxy hostname or IP (required for initialize())
 * PROXY_PORT   — proxy port number, 1–65535 (required)
 * PROXY_DOMAIN — Windows/AD domain name for NTLM (required)
 * PROXY_USER   — proxy username, without domain prefix (required)
 * PROXY_PASS   — proxy password (required)
 *
 * Call initialize()        for strict mode: fails if env vars missing.
 * Call initializeIfPresent() for soft mode: no-op if PROXY_HOST not set.
 *   → Used by T21/T22/T23 so the same code runs inside VPN (no proxy)
 *     and outside VPN (proxy required) without code changes.
 * ============================================================================
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

public final class CorporateProxyBootstrap {

    private static final Logger log =
            LoggerFactory.getLogger(CorporateProxyBootstrap.class);

    private CorporateProxyBootstrap() {}

    private static volatile boolean initialized = false;

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Strict bootstrap — all proxy env vars must be present.
     * Throws {@link IllegalStateException} if any required variable is missing.
     * Call this when the application is known to run behind a corporate proxy.
     */
    public static void initialize() {
        if (initialized) return;

        synchronized (CorporateProxyBootstrap.class) {
            if (initialized) return;
            doInitialize();
            initialized = true;
        }
    }

    /**
     * Soft bootstrap — no-op if PROXY_HOST is not set.
     * Call this when the same code must run in both proxy and non-proxy
     * environments (e.g. developer workstation vs. OCI Compute instance).
     *
     * <p>T21/T22/T23 use this method so the application runs unchanged
     * when deployed on OCI Compute (Instance Principal, no proxy needed).
     */
    public static void initializeIfPresent() {
        String host = System.getenv("PROXY_HOST");
        if (host == null || host.isBlank()) {
            log.debug("PROXY_HOST not set — skipping proxy bootstrap.");
            return;
        }
        initialize();
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    private static void doInitialize() {
        String host   = requireEnv("PROXY_HOST");
        String port   = requireEnv("PROXY_PORT");
        String domain = requireEnv("PROXY_DOMAIN");
        String user   = requireEnv("PROXY_USER");
        String pass   = requireEnv("PROXY_PASS");

        validatePort(port);

        // Proxy routing for OCI SDK HTTPS calls (GenerateScopedAccessToken)
        System.setProperty("https.proxyHost", host);
        System.setProperty("https.proxyPort", port);
        System.setProperty("http.proxyHost",  host);
        System.setProperty("http.proxyPort",  port);

        // Java 11+: allow NTLM in HTTPS tunneling and proxying
        // By default, Java 11 disables NTLM for security reasons.
        // These properties re-enable it for corporate AD environments.
        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        System.setProperty("jdk.http.auth.proxying.disabledSchemes", "");

        // Windows AD domain for NTLM challenge-response
        System.setProperty("http.auth.ntlm.domain", domain);

        // Authenticator for java.net.HttpURLConnection
        // NOTE: effective for JDK built-in HTTP only, NOT for Apache HttpClient.
        // OCI SDK uses Apache HttpClient → see KNOWN LIMITATION above.
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                if (getRequestorType() == RequestorType.PROXY) {
                    return new PasswordAuthentication(user, pass.toCharArray());
                }
                return null;
            }
        });

        log.info("Corporate proxy configured: {}:{} domain={} user={}",
                host, port, domain, user);
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(
                "Missing required environment variable: " + name +
                ". Set it before calling CorporateProxyBootstrap.initialize().");
        }
        return v;
    }

    private static void validatePort(String port) {
        try {
            int p = Integer.parseInt(port);
            if (p < 1 || p > 65535) {
                throw new IllegalStateException("PROXY_PORT out of range [1–65535]: " + port);
            }
        } catch (NumberFormatException e) {
            throw new IllegalStateException("PROXY_PORT is not a valid integer: " + port, e);
        }
    }
}
