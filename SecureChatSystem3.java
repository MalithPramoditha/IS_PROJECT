import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class SecureChatSystem3 {

    // Audit logging of authentication events
    public static void logAuthentication(String username) {
        try {
            Files.writeString(Paths.get("auth_log.txt"),
                    "Login by " + username + " at " + Instant.now() + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Failed to write authentication log: " + e.getMessage());
        }
    }

    // Generate Ephemeral ECDH Key Pair
    public static KeyPair generateEphemeralDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    // Perform ECDH Key Agreement
    public static SecretKey performKeyAgreement(PrivateKey privateKey, byte[] receivedPublicKeyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey receivedPublicKey = kf.generatePublic(new X509EncodedKeySpec(receivedPublicKeyBytes));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(receivedPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES"); // 128-bit AES session key
    }

    // AES-GCM Encryption
    public static byte[] encryptMessage(String message, SecretKey aesKey) throws Exception {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedWithIv = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedWithIv, iv.length, ciphertext.length);

        return encryptedWithIv;
    }

    // AES-GCM Decryption
    public static String decryptMessage(byte[] encrypted, SecretKey aesKey) throws Exception {
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[encrypted.length - 12];
        System.arraycopy(encrypted, 0, iv, 0, 12);
        System.arraycopy(encrypted, 12, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // Fingerprint for identity verification
    public static String getKeyFingerprint(PublicKey key) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(key.getEncoded());
        return Base64.getEncoder().encodeToString(digest);
    }

    public static void main(String[] args) throws Exception {
        // Authentication logging
        String userA = "alice";
        logAuthentication(userA);

        // ECDH key exchange
        KeyPair aliceKeyPair = generateEphemeralDHKeyPair();
        KeyPair bobKeyPair = generateEphemeralDHKeyPair();

        byte[] alicePubKey = aliceKeyPair.getPublic().getEncoded();
        byte[] bobPubKey = bobKeyPair.getPublic().getEncoded();

        SecretKey aliceSessionKey = performKeyAgreement(aliceKeyPair.getPrivate(), bobPubKey);
        SecretKey bobSessionKey = performKeyAgreement(bobKeyPair.getPrivate(), alicePubKey);

        System.out.println("Session keys match: " + MessageDigest.isEqual(
                aliceSessionKey.getEncoded(), bobSessionKey.getEncoded()));

        // Identity verification
        System.out.println("Alice Fingerprint: " + getKeyFingerprint(aliceKeyPair.getPublic()));
        System.out.println("Bob Fingerprint: " + getKeyFingerprint(bobKeyPair.getPublic()));

        // Secure messaging
        String message = "Hello from Alice to Bob!";
        byte[] encrypted = encryptMessage(message, aliceSessionKey);
        String decrypted = decryptMessage(encrypted, bobSessionKey);

        System.out.println("Original Message: " + message);
        System.out.println("Decrypted Message: " + decrypted);
    }

}
