package com.example.SecureJWT.controller;

import com.example.SecureJWT.dto.MemberLoginRequestDto;
import com.example.SecureJWT.dto.TokenInfoDTO;
import com.example.SecureJWT.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final MemberService memberService;

    // AccessToken 발급
    @PostMapping("/login")
    public TokenInfoDTO login(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        TokenInfoDTO tokenInfoDTO = memberService.login(memberId, password);
        return tokenInfoDTO;
    }

    // AccessToken 테스트
    @GetMapping("/check")
    public String check() {
        log.info("only ADMIN");
        return "only ADMIN";
    }

    // test
    @GetMapping("/test")
    public String test() {
        log.info("test");
        return "test";
    }

    @GetMapping("/onlyUser")
    public String onlyUser() {
        log.info("only User");
        return "only User";
    }
}
