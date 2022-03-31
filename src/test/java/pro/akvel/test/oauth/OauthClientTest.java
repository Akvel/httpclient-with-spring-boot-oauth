package pro.akvel.test.oauth;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author akvel
 * @since 31.03.2022
 */
@SpringBootTest
@WireMockTest(httpPort = 8089)
public class OauthClientTest {

    private static final String SSO_TOKEN_RESPONSE = "{ " +
            "\"access_token\": \"my-token\"," +
            "\"expires_in\": 60," +
            "\"refresh_expires_in\": 1800," +
            "\"refresh_token\": \"my-refresh-token\"," +
            "\"token_type\": \"bearer\"" +
            "}";

    @Autowired
    private HttpClient httpClient;

    @Test
    void test_authorization(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
        stubFor(post("/auth/realms/my-realm/protocol/openid-connect/token")
                .withBasicAuth("this-is-my-client", "this-is-my-client-secret")
                .withRequestBody(equalTo("grant_type=password&username=this-is-my-login&password=this-is-my-password"))
                .willReturn(okJson(SSO_TOKEN_RESPONSE)));

        stubFor(post("/test")
                .withHeader("Authorization", equalTo("Bearer my-token"))
                .willReturn(ok("Hello world")));

        var post = RequestBuilder.post("http://localhost:8089/test")
                .setEntity(new StringEntity("Hello world", ContentType.TEXT_PLAIN))
                .build();

        var response = httpClient.execute(post);

        assertEquals(200, response.getStatusLine().getStatusCode());
        assertEquals("Hello world", EntityUtils.toString(response.getEntity(), "UTF-8"));
    }


}
