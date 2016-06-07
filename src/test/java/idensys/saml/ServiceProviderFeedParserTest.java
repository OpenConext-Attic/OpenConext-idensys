package idensys.saml;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.util.Collection;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ServiceProviderFeedParserTest {

  private ServiceProviderFeedParser parser = new ServiceProviderFeedParser(new ClassPathResource("saml/eb.sp.metadata.xml"));

  @Test
  public void testParse() throws Exception {
    Collection<ServiceProvider> serviceProviders = parser.parse().values();

    assertEquals(1, serviceProviders.size());
    List<ServiceProvider> signed = serviceProviders.stream().filter(sp -> sp.isSigningCertificateSigned()).collect(toList());
    assertEquals(1, signed.size());

    serviceProviders.forEach(sp -> assertFalse(sp.getAssertionConsumerServiceURLs().isEmpty()));
  }




}
