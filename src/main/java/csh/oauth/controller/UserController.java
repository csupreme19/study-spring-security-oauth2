package csh.oauth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/user")
    public OAuth2User user(Authentication authentication) {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oAuth2AuthenticationToken.getPrincipal();
        return oAuth2User;
    }

    @GetMapping("/oAuth2User")
    public OAuth2User oidc(@AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("{}", oAuth2User);
        return oAuth2User;
    }

    @GetMapping("/oidcUser")
    public OAuth2User oidc(@AuthenticationPrincipal OidcUser oidcUser) {
        log.info("{}", oidcUser);
        return oidcUser;
    }

}
