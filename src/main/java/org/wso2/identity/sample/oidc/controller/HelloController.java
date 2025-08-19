package org.wso2.identity.sample.oidc.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        // Pull a friendly name if present; fall back to sub
        String name =
                (String) jwt.getClaims().getOrDefault("preferred_username",
                        jwt.getClaims().getOrDefault("email", jwt.getSubject()));

        Map<String, Object> out = new HashMap<>();
        out.put("message", "Hello, " + name + " 👋");
        out.put("sub", jwt.getSubject());
        out.put("issuer", jwt.getIssuer().toString());
        out.put("scope", jwt.getClaimAsString("scope"));     // or "scp" depending on IdP
        return out;
    }

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getClaims();
    }
}