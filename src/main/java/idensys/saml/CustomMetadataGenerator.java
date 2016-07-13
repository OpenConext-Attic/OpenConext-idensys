package idensys.saml;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataGenerator;

public class CustomMetadataGenerator extends MetadataGenerator {

  private ResourceMetadataProvider metadataProvider;

  public CustomMetadataGenerator(ResourceMetadataProvider metadataProvider) {
    this.metadataProvider = metadataProvider;
  }

  @Override
  public EntityDescriptor generateMetadata() {
    try {
      EntityDescriptor entityDescriptor = (EntityDescriptor) this.metadataProvider.doGetMetadata();
      return entityDescriptor;
    } catch (MetadataProviderException e) {
      throw new RuntimeException(e);
    }
  }

}
