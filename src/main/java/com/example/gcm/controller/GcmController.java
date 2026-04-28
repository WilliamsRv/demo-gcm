package com.example.gcm.controller;

import com.example.gcm.dto.CryptoResponse;
import com.example.gcm.dto.DecryptRequest;
import com.example.gcm.dto.EncryptRequest;
import com.example.gcm.service.AesGcmService;
import com.example.gcm.service.AesGcmService.EncryptionResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/gcm")
@CrossOrigin(origins = "*")
public class GcmController {

    private final AesGcmService aesGcmService;

    public GcmController(AesGcmService aesGcmService) {
        this.aesGcmService = aesGcmService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<CryptoResponse> encrypt(@RequestBody EncryptRequest request) {
        try {
            EncryptionResult result = aesGcmService.encrypt(
                request.plaintext(), 
                request.associatedData()
            );
            return ResponseEntity.ok(CryptoResponse.success(result));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(CryptoResponse.error("Error en cifrado: " + e.getMessage()));
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<CryptoResponse> decrypt(@RequestBody DecryptRequest request) {
        try {
            String plaintext = aesGcmService.decrypt(
                request.encryptedData(),
                request.key(),
                request.associatedData()
            );
            return ResponseEntity.ok(CryptoResponse.success(
                Map.of("plaintext", plaintext)
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(CryptoResponse.error("Error en descifrado: " + e.getMessage()));
        }
    }

    @GetMapping("/info")
    public ResponseEntity<CryptoResponse> getInfo() {
        return ResponseEntity.ok(CryptoResponse.success(Map.of(
            "algorithm", "AES-GCM",
            "keySize", "256 bits",
            "ivLength", "96 bits (12 bytes)",
            "authTagLength", "128 bits",
            "mode", "Authenticated Encryption with Associated Data (AEAD)"
        )));
    }
}
