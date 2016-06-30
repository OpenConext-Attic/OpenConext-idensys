package idensys.saml;

import org.opensaml.common.binding.decoding.URIComparator;

/**
 * We need to prevent
 * <p>
 * SAML message intended destination endpoint 'https://idensys.test.surfconext.nl/saml/idp/login' did not
 * match the recipient endpoint 'http://localhost:9290/saml/idp/login'
 * <p>
 * For all SP related calls this is handled by the ProxiedSAMLContextProviderLB, but for IdP calls this
 * is not supported by Spring SAML
 */
public class ProxyURIComparator implements URIComparator {

  private final String proxiedUrl;
  private final String localUrl;

  public ProxyURIComparator(String proxiedUrl, String localUrl) {
    this.proxiedUrl = proxiedUrl;
    this.localUrl = localUrl;
  }

  @Override
  public boolean compare(String uri1, String uri2) {
    if (uri1 == null || uri2 == null) {
      return uri1 == null && uri2 == null;
    }
    String uri1Canon = uri1.contains(localUrl) ? uri1.replace(localUrl, proxiedUrl) : uri1;
    String uri2Canon = uri2.contains(localUrl) ? uri2.replace(localUrl, proxiedUrl) : uri2;
    return uri1Canon.equalsIgnoreCase(uri2Canon);

  }
}
