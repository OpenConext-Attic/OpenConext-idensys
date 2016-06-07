package idensys.saml;

import org.springframework.util.StringUtils;

import java.util.List;

public class ServiceProvider {

  private final String entityId;
  private final String signingCertificate;
  private final List<String> assertionConsumerServiceURLs;

  public ServiceProvider(String entityId, String signingCertificate, List<String> assertionConsumerServiceURLs) {
    this.entityId = entityId;
    this.signingCertificate = signingCertificate;
    this.assertionConsumerServiceURLs = assertionConsumerServiceURLs;
  }

  public String getEntityId() {
    return entityId;
  }

  public String getSigningCertificate() {
    return signingCertificate;
  }

  public List<String> getAssertionConsumerServiceURLs() {
    return assertionConsumerServiceURLs;
  }

  public boolean isSigningCertificateSigned() {
    return StringUtils.hasText(signingCertificate);
  }
}
