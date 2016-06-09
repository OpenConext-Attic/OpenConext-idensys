package idensys.saml;

import org.apache.commons.httpclient.HttpClient;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;

public class ConfigurableArtifactResolutionProfile extends ArtifactResolutionProfileImpl {

  private final boolean verifyHostName;

  public ConfigurableArtifactResolutionProfile(HttpClient httpClient, boolean verifyHostName) {
    super(httpClient);
    this.verifyHostName = verifyHostName;
  }

  @Override
  protected boolean isHostnameVerificationSupported() {
    return verifyHostName;
  }
}
