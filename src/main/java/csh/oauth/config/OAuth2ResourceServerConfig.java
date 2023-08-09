package csh.oauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    private final OAuth2ResourceServerProperties properties;

    @Bean
    public SecurityFilterChain oauth2ResourceServer(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(config -> config.jwt(withDefaults()));
//        http.oauth2ResourceServer(config -> config.opaqueToken(withDefaults()));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }

}
