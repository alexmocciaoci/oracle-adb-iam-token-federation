package com.alemoccia.iam.shared;

/*
 * ============================================================================
 * OciIamDbAccessTokenFactory — OCI SDK in-process IAM DB Token factory
 * ============================================================================
 * Repository : https://github.com/alexmocciaoci/oracle-adb-iam-token-federation
 * Author     : Alessandro Moccia — Oracle Solution Architect | Oracle ACE Program
 *
 * PURPOSE
 * -------
 * Factory that generates an Oracle JDBC AccessToken by calling the OCI IAM
 * GenerateScopedAccessToken API in-process via the OCI Java SDK.
 *
 * Used by T21 (single connection) and T22 (UCP pool Supplier).
 *
 * WHAT HAPPENS INSIDE create()
 * ----------------------------
 * 1. CorporateProxyBootstrap.initializeIfPresent()
 *    → Configures NTLM proxy for OCI SDK HTTPS calls if env vars present.
 *    → No-op if PROXY_HOST not set (OCI Compute, no proxy).
 *
 * 2. AuthenticationDetailsProvider
 *    → ConfigFileAuthenticationDetailsProvider: reads ~/.oci/config API Key.
 *    → For Instance Principal:  InstancePrincipalsAuthenticationDetailsProvider
 *    → For Resource Principal:  ResourcePrincipalAuthenticationDetailsProvider
 *    → See comments in create() below.
 *
 * 3. RSA 2048 ephemeral key pair (Proof-of-Possession)
 *    → Generated client-side via KeyPairGenerator.
 *    → Public key embedded in the token by OCI IAM.
 *    → Private key stays in memory — never transmitted, never written to disk.
 *    → ojdbc17 uses the private key to sign the ADB-S PoP challenge.
 *
 * 4. GenerateScopedAccessToken via DataplaneClient
 *    → DataplaneClient wraps the OCI IAM identitydataplane REST API.
 *    → scope = "urn:oracle:db::id::*" (all ADB-S instances in tenancy).
 *    → Production recommendation: restrict to specific ADB OCID:
 *        "urn:oracle:db::id::ocid1.autonomousdatabase.oc1.[region].[id]"
 *
 * 5. AccessToken.createJsonWebToken(char[], PrivateKey)
 *    → Oracle JDBC API that wraps the JWT + private key into an AccessToken.
 *    → This AccessToken is passed to createConnectionBuilder().accessToken()
 *      or to setTokenSupplier() in a DataSource.
 *
 * TOKEN BUNDLE
 * ------------
 * Returns TokenBundle (Java 16+ record) containing:
 *   accessToken — used by JDBC (createConnectionBuilder or setTokenSupplier)
 *   rawJwt      — used by CachingIamTokenSupplier to parse the exp claim
 *
 * PROXY LIMITATION — Enhancement Requests T14/T15
 * ------------------------------------------------
 * In NTLM proxy environments, the OCI Java SDK (ApacheConnectorProvider)
 * does not use java.net.Authenticator for proxy credentials. The HTTPS call
 * to OCI IAM fails with HTTP 407.
 * Workaround: use T19/T20 (OCI CLI subprocess) in proxy environments.
 * See CorporateProxyBootstrap.java for full details.
 *
 * REFERENCES
 * ----------
 * OCI Java SDK — DataplaneClient:
 *   https://docs.oracle.com/en-us/iaas/tools/java/latest/com/oracle/bmc/identitydataplane/DataplaneClient.html
 * ojdbc17 — AccessToken:
 *   https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/client-side-security.html
 * OCI Java SDK — Instance Principal:
 *   https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/javasdk.htm#Instance_Principal_Authentication
 * OCI Java SDK — Resource Principal:
 *   https://docs.oracle.com/en-us/iaas/tools/java/latest/com/oracle/bmc/auth/ResourcePrincipalAuthenticationDetailsProvider.html
 * ============================================================================
 */

import com.oracle.bmc.auth.AbstractAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
// Uncomment for OCI Compute Instance Principal (no API Key required):
// import com.oracle.bmc.auth.InstancePrincipalsAuthenticationDetailsProvider;
// Uncomment for OCI Functions / OKE Resource Principal:
// import com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider;
import com.oracle.bmc.identitydataplane.DataplaneClient;
import com.oracle.bmc.identitydataplane.model.GenerateScopedAccessTokenDetails;
import com.oracle.bmc.identitydataplane.requests.GenerateScopedAccessTokenRequest;
import oracle.jdbc.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

public final class OciIamDbAccessTokenFactory {

    private static final Logger log =
            LoggerFactory.getLogger(OciIamDbAccessTokenFactory.class);

    private OciIamDbAccessTokenFactory() {}

    /**
     * Result record — carries both the JDBC AccessToken and the raw JWT string.
     *
     * @param accessToken  JDBC AccessToken wrapping JWT + private key (for ojdbc17)
     * @param rawJwt       Raw JWT string — used to parse {@code exp} claim for caching
     */
    public record TokenBundle(AccessToken accessToken, String rawJwt) {}

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Generates an Oracle JDBC {@link AccessToken} using OCI Java SDK in-process.
     *
     * <p>Supports three authentication patterns via comment switches:
     * <ol>
     *   <li><b>API Key</b> (default) — reads {@code ~/.oci/config}.
     *       Use for: developer workstations, on-premises M2M, CI/CD.</li>
     *   <li><b>Instance Principal</b> — OCI Compute VM/BM. No credential file.
     *       OCI hypervisor authenticates via IMDS. No proxy needed.</li>
     *   <li><b>Resource Principal</b> — OCI Functions / OKE pods.
     *       Runtime-injected credential. Zero credential material in code.</li>
     * </ol>
     *
     * @param ociProfile OCI config profile name (e.g. "DEFAULT").
     *                   Ignored for Instance/Resource Principal.
     * @return {@link TokenBundle} with AccessToken and raw JWT.
     * @throws Exception if OCI IAM call fails, proxy blocks, or key gen fails.
     */
    public static TokenBundle create(String ociProfile) throws Exception {
        Objects.requireNonNull(ociProfile, "ociProfile must not be null");

        // Step 1 — Configure proxy if present (soft: no-op if PROXY_HOST not set)
        CorporateProxyBootstrap.initializeIfPresent();

        // Step 2 — Authentication provider
        // ─── OPTION A: API Key from ~/.oci/config (default, on-premises / dev) ─────
        AbstractAuthenticationDetailsProvider authProvider =
                new ConfigFileAuthenticationDetailsProvider(ociProfile);

        // ─── OPTION B: Instance Principal (OCI Compute — uncomment to use) ─────────
        // No credential file. OCI hypervisor authenticates via IMDS (internal network).
        // Dynamic Group required: All {instance.compartment.id = 'ocid1.compartment...'}
        // AbstractAuthenticationDetailsProvider authProvider =
        //         InstancePrincipalsAuthenticationDetailsProvider.builder().build();

        // ─── OPTION C: Resource Principal (OCI Functions / OKE — uncomment to use) ─
        // Runtime-injected credential. Zero credential material in application code.
        // Dynamic Group required: All {resource.type = 'fnfunc', resource.compartment.id = '...'}
        // AbstractAuthenticationDetailsProvider authProvider =
        //         ResourcePrincipalAuthenticationDetailsProvider.builder().build();

        // Step 3 — Ephemeral RSA 2048 key pair (Proof-of-Possession)
        // Public key is embedded in the JWT by OCI IAM.
        // Private key stays in memory — used by ojdbc17 to sign the ADB-S PoP challenge.
        KeyPair keyPair = generateEphemeralRsaKeyPair();

        // Step 4 — Call OCI IAM GenerateScopedAccessToken
        String jwt = requestScopedToken(authProvider, keyPair.getPublic());
        log.debug("JWT acquired — length: {} chars", jwt.length());

        // Step 5 — Wrap JWT + private key into JDBC AccessToken
        AccessToken accessToken = AccessToken.createJsonWebToken(
                jwt.toCharArray(),
                keyPair.getPrivate());

        return new TokenBundle(accessToken, jwt);
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    private static KeyPair generateEphemeralRsaKeyPair() throws Exception {
        // RSA 2048 matches the key size used by the OCI CLI (oci_db_key.pem).
        // The public key is encoded as DER/Base64 for the OCI IAM API.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String requestScopedToken(
            AbstractAuthenticationDetailsProvider authProvider,
            PublicKey publicKey) throws Exception {

        // OCI IAM requires the public key as Base64-encoded DER (PKCS#8 SubjectPublicKeyInfo)
        String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        // Scope: "urn:oracle:db::id::*" grants access to all ADB-S instances in the tenancy.
        // Production recommendation: restrict to specific ADB OCID:
        //   "urn:oracle:db::id::ocid1.autonomousdatabase.oc1.[region].[unique_id]"
        String scope = "urn:oracle:db::id::*";

        GenerateScopedAccessTokenDetails details =
                GenerateScopedAccessTokenDetails.builder()
                        .publicKey(base64PublicKey)
                        .scope(scope)
                        .build();

        GenerateScopedAccessTokenRequest request =
                GenerateScopedAccessTokenRequest.builder()
                        .generateScopedAccessTokenDetails(details)
                        .build();

        // DataplaneClient implements AutoCloseable — try-with-resources closes it cleanly.
        // It wraps the OCI IAM identitydataplane REST API (/v1/actions/generateScopedAccessToken).
        // The SDK signs the HTTPS request with the authProvider credentials (API Key / IMDS / RPST).
        try (DataplaneClient client = DataplaneClient.builder().build(authProvider)) {
            String jwt = client.generateScopedAccessToken(request)
                    .getSecurityToken()  // → SecurityToken object
                    .getToken();         // → JWT string (RFC 7519)

            log.info("GenerateScopedAccessToken succeeded via {}", authProvider.getClass().getSimpleName());
            return jwt;
        }
    }
}
