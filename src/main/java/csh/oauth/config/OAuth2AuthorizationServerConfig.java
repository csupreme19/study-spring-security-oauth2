package csh.oauth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;

@Configuration
public class OAuth2AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain oauth2AuthorizationServer(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(e -> {
            e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        });
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("myclient")
                .clientId("oauth2-client-app")
                .clientSecret("{noop}5Dne0c09qKG7XnS43p5RQzgETH6mYdYc")
                .clientAuthenticationMethods(c -> {
                    c.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantTypes(a -> {
                    a.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                })
                .redirectUri("http://localhost:8081/login/oauth2/code/myclient")
                .scopes(s -> {
                    s.addAll(List.of("openid", "profile", "email"));
                })
                .clientName("oauth2-client-app")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        InMemoryRegisteredClientRepository repository = new InMemoryRegisteredClientRepository(registeredClient);
        return repository;
    }

}
