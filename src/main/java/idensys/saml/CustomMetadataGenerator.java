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

//  @Override
//  protected SPSSODescriptor buildSPSSODescriptor(String entityBaseURL, String entityAlias, boolean requestSigned, boolean wantAssertionSigned, Collection<String> includedNameID) {
//    SPSSODescriptor descriptor = super.buildSPSSODescriptor(entityBaseURL, entityAlias, requestSigned, wantAssertionSigned, includedNameID);
//
//    AttributeConsumingService attributeConsumingServices = buildSAMLObject(AttributeConsumingService.class, AttributeConsumingService.DEFAULT_ELEMENT_NAME);
//    attributeConsumingServices.setIndex(1);
//    ServiceName serviceName = buildSAMLObject(ServiceName.class, ServiceName.DEFAULT_ELEMENT_NAME);
//
//    serviceName.setName(new LocalizedString("SURFnet Idensys TEST", "nl"));
//    attributeConsumingServices.getNames().add(serviceName);
//    RequestedAttribute requestedAttribute = buildSAMLObject(RequestedAttribute.class, RequestedAttribute.DEFAULT_ELEMENT_NAME);
//    requestedAttribute.setName("urn:etoegang:DV:00000003300907770000:services:0001");
//    attributeConsumingServices.getRequestAttributes().add(requestedAttribute);
//
//    descriptor.getAttributeConsumingServices().add(attributeConsumingServices);
//
////    Organization organization = buildSAMLObject(Organization.class, Organization.DEFAULT_ELEMENT_NAME);
////    OrganizationDisplayName displayName = buildSAMLObject(OrganizationDisplayName.class, buildSAMLObject
////    organization.getDisplayNames().add(organizationD)
////    descriptor.setOrganization(organization);
//    return descriptor;
//  }
}
