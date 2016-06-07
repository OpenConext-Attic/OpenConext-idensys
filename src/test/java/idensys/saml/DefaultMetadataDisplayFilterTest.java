package idensys.saml;

import idensys.AbstractIntegrationTest;
import org.junit.Test;

import static org.junit.Assert.*;

public class DefaultMetadataDisplayFilterTest extends AbstractIntegrationTest{

  @Test
  public void testProcessMetadataDisplay() throws Exception {
    String metadata = restTemplate.getForObject("http://localhost:" + port + "/sp/metadata", String.class);
    assertTrue(metadata.contains("entityID=\"https://idensys.localhost.surfconext.nl\""));
  }
}
