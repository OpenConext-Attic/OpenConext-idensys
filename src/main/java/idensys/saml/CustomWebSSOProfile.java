package idensys.saml;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

public class CustomWebSSOProfile extends WebSSOProfileImpl {

  protected void buildReturnAddress(AuthnRequest request, AssertionConsumerService service) throws MetadataProviderException {
    // AssertionConsumerServiceURL + ProtocolBinding is mutually exclusive with AssertionConsumerServiceIndex, we use the second option here
    request.setAssertionConsumerServiceIndex(1);
  }
}
