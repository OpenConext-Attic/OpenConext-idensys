package idensys.web;


import org.junit.Test;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.ResponseEntity;

import java.util.Optional;

import static org.junit.Assert.assertNotNull;


@WebIntegrationTest(value = {"server.port=0", "spring.profiles.active=dev", "serviceproviders.allow_unknown=true"})
public class AllowAllWebSecurityConfigTest extends AbstractWebSecurityConfigTest {

  @Test
  public void testInvalidEntityIDButAllowed() throws Exception {
    String url = samlRequestUtils.redirectUrl("http://bogus", "http://localhost:" + port + "/saml/idp", acsLocation, Optional.empty(), false);

    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
    String saml = decodeSamlArtifactRedirect(response);

    assertNotNull(saml);
  }

}
