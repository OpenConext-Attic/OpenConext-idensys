package idensys.saml;

import org.junit.Test;

import static org.junit.Assert.*;

public class ProxyURIComparatorTest {

  private ProxyURIComparator subject = new ProxyURIComparator("https://idensys.test.surfconext.nl", "http://localhost:9290");

  @Test
  public void testCompare() throws Exception {
    assertFalse(subject.compare("https://idensys.test.surfconext.nl/saml/idp/login", null));
    assertFalse(subject.compare(null, "https://idensys.test.surfconext.nl/saml/idp/login"));

    assertTrue(subject.compare(null, null));
    assertTrue(subject.compare("https://idensys.test.surfconext.nl/saml/idp/login", "http://localhost:9290/saml/idp/login"));
    assertTrue(subject.compare("http://localhost:9290/saml/idp/login", "https://idensys.test.surfconext.nl/saml/idp/login"));
  }
}
