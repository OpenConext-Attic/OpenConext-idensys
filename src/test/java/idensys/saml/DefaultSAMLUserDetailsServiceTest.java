package idensys.saml;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class DefaultSAMLUserDetailsServiceTest {

  private DefaultSAMLUserDetailsService subject = new DefaultSAMLUserDetailsService();

  @Before
  public void before() {
    SecurityContextHolder.clearContext();
  }

  @Test(expected = IllegalArgumentException.class)
  public void testLoadUserBySAML() throws Exception {
    subject.loadUserBySAML(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testLoadUserBySAMLNoPrincipal() throws Exception {
    SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("Principal", "N/A"));
    subject.loadUserBySAML(null);
  }
}
