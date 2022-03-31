package pro.akvel.test.oauth.configuration;

import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthState;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import pro.akvel.test.oauth.authschema.OAuthSchema;
import pro.akvel.test.oauth.authschema.OauthCredentials;

import static org.apache.http.client.protocol.HttpClientContext.TARGET_AUTH_STATE;

/**
 * Apache Http Client configuration
 *
 * @author akvel
 * @since 31.03.2022
 */
@Configuration
public class ApacheHttpClientConfiguration {

    @Bean
    OauthCredentials oauthCredentials(
            @Value("${oauth-client.client-id}") String clientId,
            @Value("${oauth-client.login}") String login,
            @Value("${oauth-client.password}") String password) {
        return new OauthCredentials(clientId, login, password);
    }

    @Bean
    OAuthSchema oAuthSchema(OAuth2AuthorizedClientManager authorizedClientManager) {
        return new OAuthSchema(authorizedClientManager);
    }

    @Bean
    public CloseableHttpClient oauthHttpClient(OAuthSchema oAuthSchema,
                                               OauthCredentials oauthCredentials) {
        return HttpClients.custom()
                //Oauth is preauthenticate type, so enable it
                .addInterceptorFirst((HttpRequestInterceptor) (request, context) -> {
                    AuthState authState = (AuthState) context.getAttribute(TARGET_AUTH_STATE);
                    if (authState.getAuthScheme() == null) {
                        authState.update(oAuthSchema, oauthCredentials);
                    }
                })
                .build();
    }
}
