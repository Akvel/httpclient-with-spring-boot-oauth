package pro.akvel.test.oauth.authschema;

import org.apache.http.auth.UsernamePasswordCredentials;

import static java.util.Objects.requireNonNull;

/**
 * Oauth creds holder
 *
 * @author akvel
 * @since 31.03.2022
 */
public class OauthCredentials extends UsernamePasswordCredentials {
    private final String clientId;

    public OauthCredentials(String clientId, String userName, String password) {
        super(userName, password);
        this.clientId = requireNonNull(clientId, "clientId");
    }

    public String getClientId() {
        return clientId;
    }
}
