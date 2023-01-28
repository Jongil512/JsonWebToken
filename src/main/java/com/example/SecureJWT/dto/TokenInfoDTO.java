package com.example.SecureJWT.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenInfoDTO {

    private String grantType;
    private String accessToken;
    private String refreshToken;
}
