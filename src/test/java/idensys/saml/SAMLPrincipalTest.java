package idensys.saml;

import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.*;

public class SAMLPrincipalTest {

  private SAMLPrincipal subject = new SAMLPrincipal("entityID", "requestID", "https://acs", "relayState");

  @Test
  public void testGetName() throws Exception {
    assertNull(subject.getName());

    subject.elevate("nameID", "nameIDType", Collections.emptyList());
    assertEquals("nameID", subject.getName());
  }

  @Test
  public void testToString() throws Exception {
    assertTrue(subject.toString().contains("requestID"));
  }

  @Test
  public void testEquals() throws Exception {
    subject.elevate("nameID", "nameIDType", Collections.emptyList());

    SAMLPrincipal principal = new SAMLPrincipal("X", "X", "X", "X");
    principal.elevate("nameID", "nameIDType", Collections.emptyList());

    assertTrue(subject.equals(principal));
    assertEquals(principal.hashCode(), subject.hashCode());
  }
}
