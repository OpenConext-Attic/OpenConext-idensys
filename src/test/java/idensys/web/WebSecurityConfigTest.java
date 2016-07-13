package idensys.web;


import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.unbescape.html.HtmlEscape;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@WebIntegrationTest(value = {
  "server.port=0",
  "spring.profiles.active=dev, local",
  "idp.metadata_url=classpath:saml/idensys.test.metadata.saml.xml",
  "idp.verify_host_name=false"})
public class WebSecurityConfigTest extends AbstractWebSecurityConfigTest {

  @Value("${proxy.acs_location}")
  private String serviceProviderACSLocation;

  @Value("${proxy.entity_id}")
  private String serviceProviderEntityId;

  @Rule
  public WireMockRule digidentityWireMock = new WireMockRule(9999) ;

  @Test
  public void testInvalidSignature() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    String url = samlRequestUtils.redirectUrl(serviceProviderEntityId, "http://localhost:" + port + "/saml/idp", serviceProviderACSLocation, Optional.empty(), true);
    String mangledUrl = url.replaceFirst("&Signature[^&]+", "&Signature=bogus");

    doAssertInvalidResponse("Exception during validation of AuthnRequest (Error during signature verification)", mangledUrl);
  }
  @Test
  public void testProxyHappyFlow() throws Exception {
    String url = samlRequestUtils.redirectUrl(entityId, "http://localhost:" + port + "/saml/idp", acsLocation, Optional.empty(), true);

    ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
    HttpHeaders httpHeaders = buildCookieHeaders(response);

    response = getSAMLResponse(response, httpHeaders);

    assertEquals(200, response.getStatusCode().value());

    //we expect the automatic posting of the form back to the SP
    String body = response.getBody();
    assertTrue(body.contains("<body onload=\"document.forms[0].submit()\">"));
    assertTrue(body.contains("<input type=\"hidden\" name=\"SAMLResponse\""));
    assertTrue(body.contains("<input type=\"hidden\" name=\"Signature\""));

    Matcher matcher = Pattern.compile("<form action=\"(.*?)\" method=\"post\">").matcher(body);
    assertTrue(matcher.find());
    assertEquals(acsLocation, HtmlEscape.unescapeHtml(matcher.group(1)));
  }

  @Test
  public void testProxyTestEndpoint() throws Exception {
    ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/test", String.class);
    HttpHeaders httpHeaders = buildCookieHeaders(response);

    response = getSAMLResponse(response, httpHeaders);

    assertEquals(302, response.getStatusCode().value());

    String location = response.getHeaders().getLocation().toString();
    assertEquals("http://localhost:"+port+"/test", location);

    response = restTemplate.exchange(location, HttpMethod.GET, new HttpEntity<>(httpHeaders), String.class);
    assertUserResponse(response);
  }

  private ResponseEntity<String> getSAMLResponse(ResponseEntity<String> response, HttpHeaders httpHeaders) throws URISyntaxException, IOException, MetadataProviderException {
    //This is the AuthnRequest from the idensys to the real IdP
    String saml = decodeSamlRedirect(response);

    assertTrue(saml.contains("Destination=\"https://eid.digidentity-accept.eu/hm/eh19/dv_hm\""));

    String samlResponse = getIdPSAMLResponse(saml);

    HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);
    String artifact = samlRequestUtils.artifact(metadataManager, identityProviderEntityId);

    digidentityWireMock.stubFor(post(urlEqualTo("/resolve")).willReturn(aResponse().withStatus(200).withBody(samlResponse)));

    return restTemplate.exchange("http://localhost:" + port + "/saml/SSO?SAMLart=" + artifact, HttpMethod.GET, httpEntity, String.class);
  }


  @Test
  @Ignore
  public void testSignature() throws Exception {
    String xml = samlRequestUtils.signFile(new ClassPathResource("service_catalog.xml"));
    //Copy & Paste the signature
  }

  @Test
  public void testInvalidACS() throws UnknownHostException, SecurityException, SignatureException, MarshallingException, MessageEncodingException {
    assertInvalidResponse(entityId, "http://bogus", "ServiceProvider " + entityId + " has not published ACS ");
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
    String samlResponse = IOUtils.toString(new ClassPathResource("saml/digidentity.artifactResponse.saml.xml").getInputStream());

    //Make sure the all the validations pass. We don't sign as this is in dev modus not necessary (and cumbersome)
    samlResponse = samlResponse
      .replaceAll("@@IssueInstant@@", now)
      .replaceAll("@@NotBefore@@", now)
      .replaceAll("@@NotOnOrAfter@@", date.plus(5, ChronoUnit.MINUTES).format(DateTimeFormatter.ISO_INSTANT))
      .replaceAll("@@InResponseTo@@", inResponseTo);
    return samlResponse;
  }

}
