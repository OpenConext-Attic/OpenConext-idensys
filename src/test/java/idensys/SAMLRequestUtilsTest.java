package idensys;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;


public class SAMLRequestUtilsTest extends AbstractIntegrationTest{

  @Test
  public void artifact() throws Exception {
    String artifact = samlRequestUtils.artifact(metadataManager,"urn:etoegang:HM:00000003273226310000:entities:3019");
    assertNotNull(artifact);
  }

}
