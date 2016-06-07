package idensys.saml;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.security.core.AuthenticationException;

public class SAMLAuthenticationException extends AuthenticationException {

  private final SAMLPrincipal principal;

  public SAMLAuthenticationException(String message, Exception exception, BasicSAMLMessageContext messageContext) {
    super(message, exception);
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
    this.principal = new SAMLPrincipal(
      authnRequest.getProviderName(),
      authnRequest.getID(),
      authnRequest.getAssertionConsumerServiceURL(),
      messageContext.getRelayState());
  }

  public SAMLAuthenticationException(String message, Exception exception,SAMLPrincipal principal) {
    super(message, exception);
    this.principal = principal;
  }

  public SAMLPrincipal getPrincipal() {
    return principal;
  }
}
