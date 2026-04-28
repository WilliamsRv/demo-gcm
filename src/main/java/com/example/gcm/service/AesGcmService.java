package com.example.gcm.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AesGcmService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 256;

    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptionResult encrypt(String plaintext, String associatedData) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        SecretKey secretKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        if (associatedData != null && !associatedData.isEmpty()) {
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        }

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        byte[] combined = buffer.array();

        return new EncryptionResult(
            Base64.getEncoder().encodeToString(combined),
            Base64.getEncoder().encodeToString(secretKey.getEncoded()),
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(ciphertext),
            associatedData
        );
    }

    public String decrypt(String encryptedData, String keyBase64, String associatedData) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedData);

        ByteBuffer buffer = ByteBuffer.wrap(combined);
        byte[] iv = new byte[GCM_IV_LENGTH];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        if (associatedData != null && !associatedData.isEmpty()) {
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        }

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public record EncryptionResult(
        String encryptedData,
        String key,
        String iv,
        String ciphertext,
        String associatedData
    ) {}
}
