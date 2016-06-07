package idensys.saml;

import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.Assert.*;

public class ProxiedSAMLContextProviderLBTest {

  @Test
  public void testLocalHost() throws URISyntaxException, MetadataProviderException {
    assertRequestURL("http://localhost:8080");
    assertRequestURL("https://attribute-mapper.test.surfconext.nl");
  }

  private void assertRequestURL(String url) throws URISyntaxException, MetadataProviderException {
    ProxiedSAMLContextProviderLB subject = new ProxiedSAMLContextProviderLB(new URI(url));
    SAMLMessageContext context = new SAMLMessageContext();

    subject.populateGenericContext(new MockHttpServletRequest(), new MockHttpServletResponse(), context);

    String requestURL = ((HttpServletRequestAdapter) context.getInboundMessageTransport()).getWrappedRequest().getRequestURL().toString();
    assertEquals(url, requestURL);
  }

}
