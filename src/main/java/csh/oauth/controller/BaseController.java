package csh.oauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

}
