package org.wso2.identity.sample.oidc.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfig {

    private static final String JWKS =
            "https://api.asgardeo.io/t/bprocess/oauth2/jwks";

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withJwkSetUri(JWKS)
                .jwtProcessorCustomizer((ConfigurableJWTProcessor<SecurityContext> p) -> {
                    // Accept both "JWT" and "at+jwt"
                    p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                            JOSEObjectType.JWT,
                            new JOSEObjectType("at+jwt")
                    ));
                })
                .build();
    }
}