// src/main/java/.../controller/HelloController.java
package org.wso2.identity.sample.oidc.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HelloController {

    // WORKER-only (per SecurityConfig)
    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> out = new HashMap<>();
        out.put("message", "Hello WORKER 👷");
        out.put("sub", jwt.getSubject());
        return out;
    }

    // ADMIN-only (per SecurityConfig)
    @GetMapping("/helloRestrict")
    public Map<String, Object> helloRestrict(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> out = new HashMap<>();
        out.put("message", "Hello ADMIN 👑");
        out.put("sub", jwt.getSubject());
        return out;
    }
}