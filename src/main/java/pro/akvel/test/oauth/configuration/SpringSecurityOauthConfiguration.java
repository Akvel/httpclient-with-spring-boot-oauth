package pro.akvel.test.oauth.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME;
import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME;
import static org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder.builder;

/**
 * Spring Security OAuth context configuratuin
 *
 * @author akvel
 * @since 31.03.2022
 */
@Configuration
public class SpringSecurityOauthConfiguration {

    @Bean
    OAuth2AuthorizedClientService oAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                          OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        //configure tokens storage
        var authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                oAuth2AuthorizedClientService
        );
        //configure allowed auth types
        authorizedClientManager.setAuthorizedClientProvider(builder()
                .refreshToken()
                .password()
                .build()
        );
        //configure allowed for override attributes
        authorizedClientManager.setContextAttributesMapper(authorizeRequest ->
                Map.of(USERNAME_ATTRIBUTE_NAME, requireNonNull(authorizeRequest.getAttribute(USERNAME_ATTRIBUTE_NAME)),
                        PASSWORD_ATTRIBUTE_NAME, requireNonNull(authorizeRequest.getAttribute(PASSWORD_ATTRIBUTE_NAME))
                )
        );

        return authorizedClientManager;
    }
}
