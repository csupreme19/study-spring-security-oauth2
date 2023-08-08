package csh.oauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
public class BaseController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("keycloak");
        String clientId = registration.getClientId();
        String clientSecret = registration.getClientSecret();
        String clientName = registration.getClientName();
        return String.format("Hello %s(%s, %s)!", clientName, clientId, clientSecret);
    }

    @GetMapping("/user")
    public OAuth2User user(String accessToken) {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);
        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(registration, oAuth2AccessToken);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);
        return oAuth2User;
    }

    @GetMapping("/oidc")
    public OAuth2User oidc(String accessToken, String idToken) {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("keycloak");

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/certs").build();
        jwtDecoder.setJwtValidator((jwt) -> { return OAuth2TokenValidatorResult.success();});
        Jwt jwt = jwtDecoder.decode(idToken);
        String iss = jwt.getClaimAsString(IdTokenClaimNames.ISS);
        String sub = jwt.getClaimAsString(IdTokenClaimNames.SUB);
        String preferredUsername = jwt.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME);

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);
        OidcIdToken oidcIdToken = OidcIdToken.withTokenValue(idToken)
                .claims(claims -> {
                    claims.put(IdTokenClaimNames.ISS, iss);
                    claims.put(IdTokenClaimNames.SUB, sub);
                    claims.put(StandardClaimNames.PREFERRED_USERNAME, preferredUsername);
                }).issuedAt(Instant.now())
                .expiresAt(Instant.MAX)
                .build();
        OidcUserRequest oidcUserRequest = new OidcUserRequest(registration, oAuth2AccessToken, oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(oidcUserRequest);
        return oidcUser;
    }

}
