package csh.oauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class BaseController {

//    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
//        ClientRegistration keycloak = clientRegistrationRepository.findByRegistrationId("keycloak");
//        String clientId = keycloak.getClientId();
//        String clientSecret = keycloak.getClientSecret();
//        String clientName = keycloak.getClientName();
//        return String.format("Hello %s(%s, %s)!", clientName, clientId, clientSecret);
        return "hello";
    }

}
