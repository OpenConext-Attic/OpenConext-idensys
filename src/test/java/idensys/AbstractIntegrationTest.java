package idensys;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebIntegrationTest(value = {"server.port=0", "spring.profiles.active=dev"})
public abstract class AbstractIntegrationTest {

  protected RestTemplate restTemplate = new TestRestTemplate();

  @Value("${local.server.port}")
  protected int port;

  @Autowired
  private KeyManager keyManager;

  protected SAMLRequestUtils samlRequestUtils;

  @Before
  public void before() throws IOException {
    samlRequestUtils = new SAMLRequestUtils(keyManager);
  }

  protected HttpHeaders buildCookieHeaders(ResponseEntity<?> response) {
    List<String> cookies = response.getHeaders().get("Set-Cookie");
    assertEquals(1, cookies.size());

    //Something like JSESSIONID=j2qqhxkq9wfy1ngsqouvebxud;Path=/
    String sessionId = cookies.get(0);

    HttpHeaders requestHeaders = new HttpHeaders();
    requestHeaders.add("Cookie", sessionId.replaceAll(";.*", ""));
    return requestHeaders;
  }

  protected Map<String, String> queryParameters(String url) throws URISyntaxException {
    return asList(url.substring(url.indexOf("?") + 1).split("&")).stream()
      .map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> decode(s[1])));
  }

  private String decode(String encoded) {
    try {
      return URLDecoder.decode(encoded, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }


}
