package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JwtValidationLambda implements RequestHandler<Map<String, Object>, Map<String, Object>> {
    private static final String PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmJNt5DXZxOhP72DwAKg5fJ2tZYAsyVWZiw0EpXEsH1h6oGtjHRlOayLR66aKKuebn6wB4TofhPx4g9SslXbjTkfGPjEZCqrhmpwruAX863dRLJ8Yv19SM1tvGI6QQC85eKrhV5VJ1FNkajPTBXWg0kAWFW55WI3HqFoHB3Qb2mn84+21nMw4hQl3TpjR5HqEz4aOJY2WVlCr3daQ8rN7U0kwX/HyFcx0rJ6zHSSpgvG7yD99yDJ/EVdfi2tGSJrTLsnkc3n68zdIxUhTv8hIFr7WcyimWxh5Zohb2h4pYwTdT87TPf+5Mc+0zTqmHV5RWOzT0NRdlO8CfkcoZsroeQIDAQAB";

    private PublicKey getPublicKey() throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(PUBLIC_KEY_BASE64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
        Map<String, String> headers = (Map<String, String>) input.get("headers");
        String encodedToken = headers != null ? headers.get("X-OB-E2E-Token") : null;
        Map<String, Object> response = new HashMap<>();
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("Content-Type", "application/json");
        response.put("headers", responseHeaders);

        if (encodedToken == null) {
            response.put("statusCode", 401);
            response.put("body", "{\"message\":\"Missing token\"}");
            return response;
        }
        try {
            String jwt = new String(Base64.getDecoder().decode(encodedToken));
            Algorithm algorithm = Algorithm.RSA256((java.security.interfaces.RSAPublicKey) getPublicKey(), null);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(jwt);
            response.put("statusCode", 200);
            response.put("body", "{\"message\":\"Token valid\"}");
        } catch (Exception e) {
            response.put("statusCode", 401);
            response.put("body", "{\"message\":\"Invalid token\"}");
        }
        return response;
    }
}