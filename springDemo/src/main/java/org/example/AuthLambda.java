package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class AuthLambda implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    // Static RSA keys (PEM-encoded, for demo only)
    private static final String PRIVATE_KEY_PEM =
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYk23kNdnE6E/vYPAAqDl8na1lgCzJVZmLDQSlcSwfWHqga2MdGU5rItHrpooq55ufrAHhOh+E/HiD1KyVduNOR8Y+MRkKquGanCu4Bfzrd1Esnxi/X1IzW28YjpBALzl4quFXlUnUU2RqM9MFdaDSQBYVbnlYjceoWgcHdBvaafzj7bWczDiFCXdOmNHkeoTPho4ljZZWUKvd1pDys3tTSTBf8fIVzHSsnrMdJKmC8bvIP33IMn8RV1+La0ZImtMuyeRzefrzN0jFSFO/yEgWvtZzKKZbGHlmiFvaHiljBN1PztM9/7kxz7TNOqYdXlFY7NPQ1F2U7wJ+Ryhmyuh5AgMBAAECggEABQNEUdedFdWQxBYaEdjKZA2QJAIP4UuBKxWHPgzs/K39ABFBz95uz6FKEU/G6/2br3rIvbFvAKuvepv9pul23Vxepy4YxbDIjw+rdgp9p+94c3AEsaDm7qNbOozQhh38aY+qWKTMff/WuuXZ/IIZVwmzpV+cTVcBz3D/GHUYRyw1mh7ZPZCm3dcfgCOENYARQExjX2cOh1KqbjU0JZl7XAm0RC6Q5IFpqD6CS+ZMfeKF8gXnl0feZm7irm7Ek7OqjcwrTJ27dOaCf9zrt1iuNF/DTnuWalKLb2+4HE6ri+7MgV7ACN59YkAz4iHrzqlwGR8o9tiqg5ApZ1j/tTDZEwKBgQC8MdZTOB1xqZmO1LCiMHDHoen1m2S0sxjNcoYCfPliSLjtzmtXNAg+NsJy2IrUH4TDx8S8tEeRrIZtxYTdv3QpqTqrKFxUMZEhSjAWCPUsTLTUwTh8T39Zj4jeiET8fMs0VsQ4rqH7plO+6eJZCvx28lXFn3GtFuIOVAcfjpwRZwKBgQDPjEnpSh9gzo7hF+p7tvAbaws6ECmQNYPK5VgVfPbWiYP/Xez25doR69fyOXkSOIXRb1O0HbYi64J663oN9iDx1XMxWl7G9gvC+HVx78SEoMRF83YwwPT1rJLpztUrjzZ1DiJ5KAESU+kXAACBKFk98rdicuaZjt+FJ+xnx3OrHwKBgDCONzsfdlFWLd1xOOWP0/ld6CxLXI9WyiZvzu2jawCVvMj2gjFsplfO7xqMjj0uqKWOzE7XwMNwHPsDhEVmWUVKeW2hqzi51TUenAuDYiZ84AcolzdTl4r3ApxP0mTGmfM2E8iAHiD8iAzw8UqCECNsYP7tJXpANjD2MyRMOi4vAoGAA+BS4RCJVX2GHZ4cuwLHqTtukj8LB654L6no4z3aPleDJ5nReyr/z6Xf+p4oLLbxiN/TaGHFrRFI9pK/TNNz+hBKfnl5m62suo95Yg9gVDnMcKIDaxWvfYcjl0pNoOqj0bvZ2PluS7FVgSB24fKm+Ak4c5ZByExq0EnWmHmZJ3ECgYA1W5OcbAoUSol3ZGlDKCH0kbxXROq1tqWvCjkCOswHu8sSG4KMGOpIBGGNbxA+xr2lCbVjIyiQdITm8MSv5oGf2Drq5L7EVlR/0yq9gdgWP9TuLEXkXFlnryCs8ms/LDCT/brapz/mLG+4eQK1JLRQwuTLBshXeZxpLZLbuuSblg=="; // Replace with your actual private key (PKCS#8, base64, no headers)
    private static final String PUBLIC_KEY_PEM =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmJNt5DXZxOhP72DwAKg5fJ2tZYAsyVWZiw0EpXEsH1h6oGtjHRlOayLR66aKKuebn6wB4TofhPx4g9SslXbjTkfGPjEZCqrhmpwruAX863dRLJ8Yv19SM1tvGI6QQC85eKrhV5VJ1FNkajPTBXWg0kAWFW55WI3HqFoHB3Qb2mn84+21nMw4hQl3TpjR5HqEz4aOJY2WVlCr3daQ8rN7U0kwX/HyFcx0rJ6zHSSpgvG7yD99yDJ/EVdfi2tGSJrTLsnkc3n68zdIxUhTv8hIFr7WcyimWxh5Zohb2h4pYwTdT87TPf+5Mc+0zTqmHV5RWOzT0NRdlO8CfkcoZsroeQIDAQAB"; // Replace with your actual public key (X.509, base64, no headers)

    private static final PrivateKey PRIVATE_KEY = loadPrivateKey();
    private static final PublicKey PUBLIC_KEY = loadPublicKey();

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
        Map<String, String> headers = (Map<String, String>) input.get("headers");
        if (headers == null || !headers.containsKey("Authorization")) {
            return errorResponse(401, "about:blank", "Unauthorized", "Missing Authorization header", "/auth");
        }
        String authHeader = headers.get("Authorization");
        if (!authHeader.startsWith("Basic ")) {
            return errorResponse(401, "about:blank", "Unauthorized", "Invalid Authorization header", "/auth");
        }

        String base64Credentials = authHeader.substring("Basic ".length());
        String credentials;
        try {
            credentials = new String(Base64.getDecoder().decode(base64Credentials));
        } catch (IllegalArgumentException e) {
            return errorResponse(400, "about:blank", "Bad Request", "Malformed base64 credentials", "/auth");
        }
        String[] values = credentials.split(":", 2);
        if (values.length != 2) {
            return errorResponse(400, "about:blank", "Bad Request", "Invalid credentials format", "/auth");
        }
        String username = values[0];
        String password = values[1];

        // Dummy validation. Replace with real user validation.
        if (!"admin".equals(username) || !"password".equals(password)) {
            return errorResponse(401, "about:blank", "Unauthorized", "Invalid username or password", "/auth");
        }

        // JWT claims
        String email = "admin@example.com";
        String role = "admin";
        String sub = "user-123";
        long nowMillis = System.currentTimeMillis();
        long expMillis = nowMillis + 3600_000; // 1 hour

        String jwt = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(sub)
                .claim("username", username)
                .claim("email", email)
                .claim("role", role)
                .setIssuedAt(new Date(nowMillis))
                .setExpiration(new Date(expMillis))
                .signWith(PRIVATE_KEY, SignatureAlgorithm.RS256)
                .compact();

        String base64Jwt = Base64.getEncoder().encodeToString(jwt.getBytes());

        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", 200);
        response.put("headers", Map.of("Content-Type", "application/json"));
        response.put("body", "{\"token\":\"" + base64Jwt + "\"}");
        return response;
    }

    private static PrivateKey loadPrivateKey() {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(PRIVATE_KEY_PEM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    private static PublicKey loadPublicKey() {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(PUBLIC_KEY_PEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    private Map<String, Object> errorResponse(int status, String type, String title, String detail, String instance) {
        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", status);
        response.put("headers", Map.of("Content-Type", "application/problem+json"));
        String body = String.format(
                "{\"type\":\"%s\",\"title\":\"%s\",\"status\":%d,\"detail\":\"%s\",\"instance\":\"%s\"}",
                type, title, status, detail, instance
        );
        response.put("body", body);
        return response;
    }
}