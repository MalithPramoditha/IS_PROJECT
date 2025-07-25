// SecureChatSystem.java
// Secure chat with built-in password hashing (PBKDF2), RSA + AES encryption, message integrity, and replay protection

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.nio.ByteBuffer;

public class SecureChatSystem1 {

    // ========== AUTHENTICATION (PBKDF2) ==========
    public static String hashPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean checkPassword(String password, String stored) throws Exception {
        String[] parts = stored.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        String hashAttempt = hashPassword(password, salt);
        return hashAttempt.equals(stored);
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // ========== KEY GENERATION ==========
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // ========== KEY EXCHANGE ==========
    public static byte[] encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    public static SecretKey decryptAESKeyWithRSA(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String getKeyFingerprint(PublicKey key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(key.getEncoded());
        return Base64.getEncoder().encodeToString(hash);
    }

    // ========== ENCRYPT MESSAGE ==========
    public static byte[] encryptMessage(String message, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = SecureRandom.getInstanceStrong().generateSeed(12);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        String timestamp = Instant.now().toString();
        String fullMessage = timestamp + "|" + message;
        byte[] ciphertext = cipher.doFinal(fullMessage.getBytes());

        ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + ciphertext.length);
        buffer.putInt(iv.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }

    // ========== DECRYPT MESSAGE ==========
    public static String decryptMessage(byte[] input, SecretKey aesKey) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(input);
        int ivLength = buffer.getInt();
        byte[] iv = new byte[ivLength];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        String[] parts = new String(decrypted).split("\\|", 2);
        String timestamp = parts[0];
        String message = parts[1];

        Instant sent = Instant.parse(timestamp);
        Instant now = Instant.now();
        if (Math.abs(now.getEpochSecond() - sent.getEpochSecond()) > 300) {
            throw new SecurityException("Replay detected or clock skew too high.");
        }
        return message;
    }

    // ========== MAIN DEMO ==========
    public static void main(String[] args) throws Exception {
        // Simulate RSA key exchange
        KeyPair aliceRSA = generateRSAKeyPair();
        KeyPair bobRSA = generateRSAKeyPair();

        // Mutual fingerprint verification (manual step simulated)
        String aliceFp = getKeyFingerprint(aliceRSA.getPublic());
        String bobFp = getKeyFingerprint(bobRSA.getPublic());
        System.out.println("Alice FP: " + aliceFp);
        System.out.println("Bob FP:   " + bobFp);

        // Password hashing and verification demo
        String password = "super_secure_password";
        byte[] salt = generateSalt();
        String storedHash = hashPassword(password, salt);
        System.out.println("Password correct: " + checkPassword(password, storedHash));

        // Alice creates AES session key and sends to Bob
        SecretKey aesSession = generateAESKey();
        byte[] encryptedAESKey = encryptAESKeyWithRSA(aesSession, bobRSA.getPublic());
        SecretKey decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, bobRSA.getPrivate());

        // Alice sends encrypted message
        String originalMessage = "Hello Bob! This is Alice.";
        byte[] encryptedMsg = encryptMessage(originalMessage, aesSession);

        // Bob receives message and decrypts
        String receivedMessage = decryptMessage(encryptedMsg, decryptedAESKey);
        System.out.println("Received: " + receivedMessage);
    }

}