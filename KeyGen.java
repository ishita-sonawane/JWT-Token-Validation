

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyGen {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate(); // PKCS#8
        PublicKey publicKey = pair.getPublic();    // X.509

        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        System.out.println("Private Key (PKCS#8, base64, no headers):");
        System.out.println(privateKeyBase64);
        System.out.println("\nPublic Key (X.509, base64, no headers):");
        System.out.println(publicKeyBase64);
    }
}
