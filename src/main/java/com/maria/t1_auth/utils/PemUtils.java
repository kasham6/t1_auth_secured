package com.maria.t1_auth.utils;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PemUtils {
    public static RSAPrivateKey readPrivateKey(String resourcePath, String alg) {
        try (InputStream is = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Key not found in classpath: " + resourcePath);
            }
            byte[] bytes = is.readAllBytes();
            String pem = new String(bytes)
                    .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            return (RSAPrivateKey) KeyFactory.getInstance(alg).generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key: " + resourcePath, e);
        }
    }

    public static RSAPublicKey readPublicKey(String resourcePath, String alg) {
        try (InputStream is = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Key not found in classpath: " + resourcePath);
            }
            byte[] bytes = is.readAllBytes();
            String pem = new String(bytes)
                    .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(pem);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return (RSAPublicKey) KeyFactory.getInstance(alg).generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load public key: " + resourcePath, e);
        }
    }
}
