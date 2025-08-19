package org.wso2.identity.sample.oidc.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;

@Configuration
public class JwtConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:https://api.asgardeo.io/t/bprocess/oauth2}")
    private String issuer;

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(jwkSetUri)
                .jwtProcessorCustomizer((ConfigurableJWTProcessor<SecurityContext> processor) -> {
                    // Accept only "JWT" or "at+jwt"
                    processor.setJWSTypeVerifier((JOSEObjectType typ, SecurityContext ctx) -> {
                        if (typ != null) {
                            String t = typ.getType();
                            if (!"JWT".equalsIgnoreCase(t) && !"at+jwt".equalsIgnoreCase(t)) {
                                throw new BadJOSEException("JOSE typ " + t + " not allowed");
                            }
                        }
                    });
                })
                .build();

        // Validate timestamps + issuer
        OAuth2TokenValidator<Jwt> validator = JwtValidators.createDefaultWithIssuer(issuer);
        decoder.setJwtValidator(validator);

        return decoder;
    }
}