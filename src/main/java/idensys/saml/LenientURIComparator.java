package idensys.saml;

import org.opensaml.common.binding.decoding.URIComparator;

public class LenientURIComparator implements URIComparator {

  @Override
  public boolean compare(String uri1, String uri2) {
    return true;
  }
}
