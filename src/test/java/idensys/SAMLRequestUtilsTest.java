package idensys;

import org.junit.Test;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import static org.junit.Assert.*;


public class SAMLRequestUtilsTest extends AbstractIntegrationTest{

  @Test
  public void artifact() throws Exception {
    String artifact = samlRequestUtils.artifact(metadataManager,"urn:etoegang:HM:00000003273226310000:entities:3019");
    assertNotNull(artifact);
  }

}
