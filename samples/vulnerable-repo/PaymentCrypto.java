package com.example.payments;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/** Sample payment helper with deliberate cryptographic flaws. */
public class PaymentCrypto {

    // ECDAT-017: hardcoded key literal
    private static final String MASTER_KEY = "A7f3K9mQ2xR8tYuZ1vN4wL6pB0cD5eG8";

    /** ECDAT-001: MD5 used for integrity. */
    public static byte[] digest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    /** ECDAT-003 and ECDAT-005: Triple DES in ECB mode. */
    public static Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }

    /** ECDAT-005 and ECDAT-009: AES in ECB with a static IV. */
    public static Cipher weakAes() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec("0123456789abcdef".getBytes());
        return c;
    }

    /** ECDAT-008: PKCS1 v1.5 padding. */
    public static Cipher rsaLegacy() throws Exception {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }
}
