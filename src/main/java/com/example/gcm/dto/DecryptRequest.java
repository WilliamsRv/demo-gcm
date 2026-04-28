package com.example.gcm.dto;

public record DecryptRequest(
    String encryptedData,
    String key,
    String associatedData
) {}
