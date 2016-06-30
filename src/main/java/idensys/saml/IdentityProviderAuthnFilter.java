package idensys.saml;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;


public class IdentityProviderAuthnFilter extends OncePerRequestFilter implements AuthenticationEntryPoint {

  private final SAMLMessageHandler samlMessageHandler;
  private final Map<String, ServiceProvider> serviceProviders;
  private final boolean serviceProvidersAllowUnknown;

  public IdentityProviderAuthnFilter(SAMLMessageHandler samlMessageHandler,
                                     Map<String, ServiceProvider> serviceProviders,
                                     boolean serviceProvidersAllowUnknown) {
    this.samlMessageHandler = samlMessageHandler;
    this.serviceProviders = serviceProviders;
    this.serviceProvidersAllowUnknown = serviceProvidersAllowUnknown;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    if (authenticationNotRequired()) {
      sendAuthResponse(response);
      return;
    }

    if (!isSAML(request)) {
      if (!request.getRequestURI().contains("test")) {
        throw new IllegalArgumentException("No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
      }
      //sendAuthnRequest to EB
      SecurityContextHolder.getContext().setAuthentication(new SAMLAuthentication(new NoProxySAMLPrincipal()));
      request.getRequestDispatcher("/saml/login").forward(request, response);
      return;
    }

    //The SAMLRequest parameters are urlEncoded and the extraction expects unencoded parameters
//    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(new ParameterDecodingHttpServletRequestWrapper(request));
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request);

    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    SAMLPrincipal principal = new SAMLPrincipal(authnRequest.getIssuer().getValue(), authnRequest.getID(),
      authnRequest.getAssertionConsumerServiceURL(), messageContext.getRelayState());

    validateAssertionConsumerService(principal);

    SecurityContextHolder.getContext().setAuthentication(new SAMLAuthentication(principal));

    //forward to login page will trigger the sending of AuthRequest to the IdP
    request.getRequestDispatcher("/saml/login").forward(request, response);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    throws ServletException, IOException {
    if (!SAMLUtil.processFilter("/saml/idp", request)) {
      chain.doFilter(request, response);
      return;
    }
    commence(request, response, null);
  }

  private void validateAssertionConsumerService(SAMLPrincipal principal) {
    ServiceProvider serviceProvider = serviceProviders.get(principal.getServiceProviderEntityID());
    if (serviceProvider == null) {
      if (serviceProvidersAllowUnknown) {
        logger.warn("Allowing SP " + principal.getServiceProviderEntityID() + " because configured to allow unknown SPs");
        return;
      }
      throw new SAMLAuthenticationException("ServiceProvider " + principal.getServiceProviderEntityID() + " is unknown",
        null, principal);
    }
    if (!serviceProvider.getAssertionConsumerServiceURLs().contains(principal.getAssertionConsumerServiceURL())) {
      throw new SAMLAuthenticationException("ServiceProvider " + principal.getServiceProviderEntityID() + " has not published ACS "
        + principal.getAssertionConsumerServiceURL() + " in their assertionConsumerURLS: " + serviceProvider.getAssertionConsumerServiceURLs(),
        null, principal);
    }
  }

  private void sendAuthResponse(HttpServletResponse response) {
    SAMLPrincipal principal = (SAMLPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    samlMessageHandler.sendAuthnResponse(principal, response);
  }

  private boolean authenticationNotRequired() {
    Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
    return existingAuth != null && existingAuth.getPrincipal() instanceof SAMLPrincipal && existingAuth.isAuthenticated();
  }

  private boolean isSAML(HttpServletRequest request) {
    return StringUtils.hasText(request.getParameter("SAMLResponse"))
      || StringUtils.hasText(request.getParameter("SAMLRequest"));

  }

}
