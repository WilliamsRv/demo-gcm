package com.example.gcm.dto;

public record CryptoResponse(
    boolean success,
    String message,
    Object data
) {
    public static CryptoResponse success(Object data) {
        return new CryptoResponse(true, "Operación exitosa", data);
    }
    
    public static CryptoResponse error(String message) {
        return new CryptoResponse(false, message, null);
    }
}
