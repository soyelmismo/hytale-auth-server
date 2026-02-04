package com.hytale.dualauth.server;

import com.hytale.dualauth.agent.DualAuthConfig;
import com.hytale.dualauth.context.DualAuthContext;
import com.hytale.dualauth.context.DualAuthHelper;
import com.hytale.dualauth.embedded.EmbeddedJwkVerifier;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages F2P server identity token fetching and self-signed token generation.
 */
public class DualServerIdentity {
    private static final Logger LOGGER = Logger.getLogger("DualAuthAgent");
    private static volatile OctetKeyPair selfSignedKeyPair = null;
    private static final int HTTP_TIMEOUT = 5000;

    public static void refreshF2PTokens() {
        try {
            String endpoint = DualAuthConfig.F2P_SESSION_URL + "/server/identity";
            LOGGER.info("[DualAuth] Fetching F2P identity token from: " + endpoint);
            String response = fetchUrl(endpoint);
            if (response == null || response.isEmpty()) {
                generateFallbackTokens(); return;
            }
            String identityToken = extractJsonField(response, "identityToken");
            String sessionToken = extractJsonField(response, "sessionToken");
            if (identityToken == null) identityToken = extractJsonField(response, "token");
            if (identityToken != null) {
                DualServerTokenManager.setF2PTokens(sessionToken, identityToken);
                LOGGER.info("[DualAuth] F2P tokens fetched successfully");
            } else generateFallbackTokens();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[DualAuth] Failed to fetch F2P tokens: " + e.getMessage());
            generateFallbackTokens();
        }
    }

    public static void generateFallbackTokens() {
        try {
            OctetKeyPair keyPair = getOrCreateSelfSignedKeyPair();
            String issuer = DualAuthConfig.F2P_ISSUER;
            String serverUuid = getServerUuid();
            Date now = new Date();
            Date exp = new Date(now.getTime() + 3600_000L); 
            
            JWTClaimsSet idClaims = new JWTClaimsSet.Builder().issuer(issuer).subject(serverUuid).audience("hytale:client").issueTime(now).expirationTime(exp).claim("scope", "hytale:server").build();
            JWTClaimsSet sessClaims = new JWTClaimsSet.Builder().issuer(issuer).subject(serverUuid).issueTime(now).expirationTime(exp).claim("scope", "hytale:server hytale:client").build();
            
            String head = Base64URL.encode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"jwk\":" + keyPair.toPublicJWK().toJSONString() + "}") + ".";
            String identityToken = signNative(head + Base64URL.encode(idClaims.toJSONObject().toString()), keyPair);
            String sessionToken = signNative(head + Base64URL.encode(sessClaims.toJSONObject().toString()), keyPair);
            
            DualServerTokenManager.setF2PTokens(sessionToken, identityToken);
            LOGGER.info("[DualAuth] Generated self-signed fallback tokens (Native EdDSA)");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "[DualAuth] Failed to generate fallback tokens: " + e.getMessage());
        }
    }

    private static String signNative(String input, OctetKeyPair kp) throws Exception {
        PrivateKey privKey = EmbeddedJwkVerifier.toNativePrivate(kp);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privKey);
        signer.update(input.getBytes(StandardCharsets.UTF_8));
        return input + "." + Base64URL.encode(signer.sign());
    }

    private static synchronized OctetKeyPair getOrCreateSelfSignedKeyPair() throws Exception {
        if (selfSignedKeyPair == null) selfSignedKeyPair = new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
        return selfSignedKeyPair;
    }

    private static String getServerUuid() {
        String env = System.getenv("HYTALE_SERVER_AUDIENCE");
        return (env != null && !env.isEmpty()) ? env : UUID.randomUUID().toString();
    }

    public static String createDynamicIdentityToken() {
        String issuer = DualAuthContext.getIssuer() != null ? DualAuthContext.getIssuer() : DualAuthConfig.F2P_ISSUER;
        String token = EmbeddedJwkVerifier.createDynamicIdentityToken(issuer);
        if (token != null) return token;
        try {
            OctetKeyPair kp = getOrCreateSelfSignedKeyPair();
            JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer).subject(DualAuthContext.getPlayerUuid() != null ? DualAuthContext.getPlayerUuid() : UUID.randomUUID().toString()).audience("hytale:client").issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 3600_000L)).claim("scope", "hytale:server").build();
            return signNative(Base64URL.encode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"jwk\":" + kp.toPublicJWK().toJSONString() + "}") + "." + Base64URL.encode(claims.toJSONObject().toString()), kp);
        } catch (Exception e) { return null; }
    }

    private static String fetchUrl(String urlString) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(HTTP_TIMEOUT);
            conn.setReadTimeout(HTTP_TIMEOUT);
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() != 200) return null;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder(); String line;
                while ((line = r.readLine()) != null) sb.append(line);
                return sb.toString();
            }
        } catch (Exception e) { return null; } finally { if (conn != null) conn.disconnect(); }
    }

    private static String extractJsonField(String json, String fieldName) {
        try {
            String p = "\"" + fieldName + "\":\"";
            int s = json.indexOf(p); if (s < 0) return null;
            s += p.length(); int e = json.indexOf("\"", s); if (e < 0) return null;
            return json.substring(s, e);
        } catch (Exception e) { return null; }
    }
}
