package com.example.gcm.dto;

public record EncryptRequest(
    String plaintext,
    String associatedData
) {}
