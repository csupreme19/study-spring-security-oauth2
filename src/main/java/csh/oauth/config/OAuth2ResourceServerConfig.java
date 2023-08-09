package csh.oauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    @Bean
    public SecurityFilterChain oauth2ResourceServer(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request.anyRequest().authenticated());
        http.oauth2ResourceServer(config -> config.jwt(withDefaults()));
        return http.build();
    }

}
