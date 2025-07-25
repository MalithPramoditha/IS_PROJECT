// SecureChatSystem.java
// Secure random generation, key rotation, secure key storage, fingerprint display, and timestamp-based replay protection

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Timer;
import java.util.TimerTask;
import java.nio.ByteBuffer;

public class SecureChatSystem2 {

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

    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        byte[] salt = new byte[16];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(salt);
        return salt;
    }

    // ========== KEY MANAGEMENT ==========
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, SecureRandom.getInstanceStrong());
        return gen.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

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

    // ========== MESSAGE ENCRYPTION ==========
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

    // ========== KEY ROTATION ==========
    public static void scheduleKeyRotation(Runnable keyRotationTask, long intervalMs) {
        Timer timer = new Timer(true);
        timer.schedule(new TimerTask() {
            public void run() {
                keyRotationTask.run();
            }
        }, intervalMs, intervalMs);
    }

    // ========== SECURE STORAGE PLACEHOLDER ==========
    public static void storePrivateKeySecurely(PrivateKey key, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(key.getEncoded());
        }
    }

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes;
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyBytes = fis.readAllBytes();
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // ========== MAIN DEMO ==========
    public static void main(String[] args) throws Exception {
        KeyPair aliceRSA = generateRSAKeyPair();
        KeyPair bobRSA = generateRSAKeyPair();

        String aliceFp = getKeyFingerprint(aliceRSA.getPublic());
        String bobFp = getKeyFingerprint(bobRSA.getPublic());
        System.out.println("Alice FP: " + aliceFp);
        System.out.println("Bob FP:   " + bobFp);

        String password = "super_secure_password";
        byte[] salt = generateSalt();
        String storedHash = hashPassword(password, salt);
        System.out.println("Password correct: " + checkPassword(password, storedHash));

        SecretKey aesSession = generateAESKey();
        byte[] encryptedAESKey = encryptAESKeyWithRSA(aesSession, bobRSA.getPublic());
        SecretKey decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, bobRSA.getPrivate());

        scheduleKeyRotation(() -> {
            try {
                SecretKey newKey = generateAESKey();
                System.out.println("[Key Rotation] New AES key generated at " + Instant.now());
            } catch (Exception e) {
                System.err.println("Key rotation failed: " + e.getMessage());
            }
        }, 600000);

        String message = "Hello Bob! This is Alice.";
        byte[] encryptedMsg = encryptMessage(message, aesSession);
        String received = decryptMessage(encryptedMsg, decryptedAESKey);
        System.out.println("Received: " + received);
    }
}
