package idensys.saml;

import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.metadata.MetadataGenerator;

import java.util.Collection;

import static idensys.saml.SAMLBuilder.buildSAMLObject;

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
