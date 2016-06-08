package idensys.web;


import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.*;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.UnknownHostException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WebSecurityConfigTest extends AbstractWebSecurityConfigTest {

  @Value("${proxy.acs_location}")
  private String serviceProviderACSLocation;

  @Value("${proxy.entity_id}")
  private String serviceProviderEntityId;

  private String identityProviderEntityId = "urn:etoegang:HM:00000003273226310000:entities:3019";

  @Test
  public void testInvalidSignature() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    String url = samlRequestUtils.redirectUrl(serviceProviderEntityId, "http://localhost:" + port + "/saml/idp", serviceProviderACSLocation, Optional.empty(), true);
    String mangledUrl = url.replaceFirst("&Signature[^&]+", "&Signature=bogus");

    doAssertInvalidResponse("Exception during validation of AuthnRequest (Error during signature verification)", mangledUrl);
  }

  @Test
  public void testProxyTestEndpoint() throws Exception {
    ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/test", String.class);

    //This is the redirect with the SAMLart to the real IdP
    String artifact = decodeSamlArtifactRedirect(response);

    String artifactResolve = samlRequestUtils.artifactResolve("http://localhost:8080" + SAMLProcessingFilter.FILTER_URL, identityProviderEntityId, artifact);

    HttpHeaders httpHeaders = buildCookieHeaders(response);
    httpHeaders.setContentType(MediaType.TEXT_XML);

    // send the artifactResolve to the proxy
    HttpEntity<String> httpEntity = new HttpEntity<>(artifactResolve, httpHeaders);
    response = restTemplate.exchange("http://localhost:" + port + "/saml/SSO", HttpMethod.POST, httpEntity, String.class);

    assertEquals(302, response.getStatusCode().value());

    String location = response.getHeaders().getFirst("Location");
    assertEquals("http://localhost:" + port + "/test", location);

    response = restTemplate.exchange(location, HttpMethod.GET, new HttpEntity<>(httpHeaders), String.class);

    assertUserResponse(response);
  }

  @Test
  public void testInvalidACS() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    assertInvalidResponse(entityId, "http://bogus", "ServiceProvider " + entityId + " has not published ACS");
  }

  @Test
  public void testInvalidEntityID() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    String url = samlRequestUtils.redirectUrl("http://bogus", "http://localhost:" + port + "/", acsLocation, Optional.empty(), false);
    doAssertInvalidResponse("ServiceProvider http://bogus is unknown", url);
  }

  @Test
  public void testNoSAML() throws Exception {
    ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/bogus", String.class);
    assertEquals(403, response.getStatusCode().value());
  }

  private void assertUserResponse(ResponseEntity<String> response) {
    assertEquals(200, response.getStatusCode().value());

    String html = response.getBody();

    assertTrue(html.contains("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));
    assertTrue(html.contains("urn:collab:person:example.com:admin"));
    assertTrue(html.contains("j.doe@example.com"));
  }

  private String getIdPSAMLResponse(String saml) throws IOException {
    Matcher matcher = Pattern.compile("ID=\"(.*?)\"").matcher(saml);
    assertTrue(matcher.find());

    //We need the ID of the original request to mimic the real IdP authnResponse
    String inResponseTo = matcher.group(1);

    ZonedDateTime date = ZonedDateTime.now();
    String now = date.format(DateTimeFormatter.ISO_INSTANT);
    String samlResponse = IOUtils.toString(new ClassPathResource("saml/digidentity.authnResponse.saml.xml").getInputStream());

    //Make sure the all the validations pass. We don't sign as this is in dev modus not necessary (and cumbersome)
    samlResponse = samlResponse
      .replaceAll("@@IssueInstant@@", now)
      .replaceAll("@@NotBefore@@", now)
      .replaceAll("@@NotOnOrAfter@@", date.plus(5, ChronoUnit.MINUTES).format(DateTimeFormatter.ISO_INSTANT))
      .replaceAll("@@InResponseTo@@", inResponseTo);
    return samlResponse;
  }

}
