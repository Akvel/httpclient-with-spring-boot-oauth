package pro.akvel.test.oauth.authschema;

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.Credentials;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

import static java.util.Objects.requireNonNull;
import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME;
import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME;

/**
 * @author akvel
 * @since 31.03.2022
 */
public class OAuthSchema implements AuthScheme {
    private static final Logger log = LoggerFactory.getLogger(OAuthSchema.class);
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private boolean complete = false;

    public OAuthSchema(OAuth2AuthorizedClientManager authorizedClientManager) {
        this.authorizedClientManager = requireNonNull(authorizedClientManager);
    }

    @Override
    public void processChallenge(Header header) {
        log.debug("processChallenge: header={}", header);
    }

    @Override
    public String getSchemeName() {
        return "OAuth2";
    }

    @Override
    public String getParameter(String name) {
        return null;
    }

    @Override
    public String getRealm() {
        return null;
    }

    @Override
    public boolean isConnectionBased() {
        return false;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public Header authenticate(Credentials credentials, HttpRequest request) {
        var oauthRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(((OauthCredentials) credentials).getClientId())
                .principal(credentials.getUserPrincipal().getName())
                .attributes(stringObjectMap -> {
                    stringObjectMap.put(USERNAME_ATTRIBUTE_NAME, credentials.getUserPrincipal().getName());
                    stringObjectMap.put(PASSWORD_ATTRIBUTE_NAME, credentials.getPassword());
                })
                .build();

        try {
            OAuth2AuthorizedClient client = authorizedClientManager.authorize(oauthRequest);
            complete = true;
            return new BasicHeader(AUTH.WWW_AUTH_RESP, "Bearer " + requireNonNull(client).getAccessToken().getTokenValue());
        } catch (Exception e) {
            complete = false;
            throw e;
        }
    }
}
