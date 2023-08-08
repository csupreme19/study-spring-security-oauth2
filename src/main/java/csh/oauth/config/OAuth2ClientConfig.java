package csh.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ClientConfig {

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
//    }
//
//    private ClientRegistration keycloakClientRegistration() {
//        return ClientRegistrations.fromOidcIssuerLocation("http://localhost:8080/realms/oauth2")
//                .registrationId("keycloak")
//                .clientId("oauth2-client-app")
//                .clientSecret("vO5lZrIFT07yCF6pM9uiW4TSMEJKEtDf")
//                .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
//                .scope("openid")
//                .build();
//    }

    @Bean
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request.requestMatchers("/loginPage").permitAll()
                .anyRequest().authenticated());
        http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));
//        http.oauth2Client(Customizer.withDefaults());
        return http.build();
    }

}
