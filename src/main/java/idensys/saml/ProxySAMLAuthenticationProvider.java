package idensys.saml;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.util.Collection;
import java.util.List;

public class ProxySAMLAuthenticationProvider extends SAMLAuthenticationProvider {

  private static ThreadLocal<SAMLMessageContext> contextHolder = new ThreadLocal<>();

  @Override
  protected Collection<? extends GrantedAuthority> getEntitlements(SAMLCredential credential, Object userDetail) {
    return AuthorityUtils.createAuthorityList("ROLE_USER");
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
    SAMLMessageContext context = token.getCredentials();
    /*
     * We need the context when the userDetails are loaded, but it is not provided in the hook
     */
    contextHolder.set(context);
    try {
      return super.authenticate(authentication);
    } finally {
      contextHolder.remove();
    }
  }

  public static SAMLMessageContext threadLocalSAMLMessageContext() {
    return contextHolder.get();
  }
}
