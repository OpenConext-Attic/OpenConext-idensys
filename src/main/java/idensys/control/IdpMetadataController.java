package idensys.control;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.util.UUID;

import static idensys.saml.SAMLBuilder.buildSAMLObject;

@RestController
public class IdpMetadataController {

  private String metadata;
  private DateTime validUntil;

  @Autowired
  private KeyManager keyManager;

  @Autowired
  private CachingMetadataManager metadataManager;

  @Value("${proxy.base_url}")
  private String idensysBaseUrl;

  @Value("${proxy.entity_id}")
  private String entityId;

  @Value("${proxy.validity_duration_metadata_ms}")
  private int validityDurationMetadataMilliseconds;

  @Value("${proxy.base_url}")
  private String baseUrl;

  @Value("${proxy.key_name}")
  private String proxyKeyName;

  @RequestMapping(method = RequestMethod.GET, value = "/idp/metadata", produces = "application/xml")
  public String metadata() throws SecurityException, ParserConfigurationException, SignatureException, MarshallingException, TransformerException {
//    if (metadata == null || this.validUntil.isBeforeNow()) {
      this.metadata = generateMetadata();
//    }
    return this.metadata;
  }

  private String generateMetadata() throws SecurityException, SignatureException, MarshallingException, ParserConfigurationException, TransformerException {
    this.validUntil = new DateTime().plusMillis(validityDurationMetadataMilliseconds);

    EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
    entityDescriptor.setEntityID(entityId);
    entityDescriptor.setID(UUID.randomUUID().toString());
    entityDescriptor.setValidUntil(this.validUntil);

    IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

    NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
    nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    idpssoDescriptor.getNameIDFormats().add(nameIDFormat);

    idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

    SingleSignOnService singleSignService = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    singleSignService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
    singleSignService.setLocation(baseUrl + "/saml/idp/login");
    idpssoDescriptor.getSingleSignOnServices().add(singleSignService);

    X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    keyInfoGeneratorFactory.setEmitEntityCertificate(true);
    KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

    Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
    KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
    encKeyDescriptor.setUse(UsageType.SIGNING);
    KeyInfo keyInfo = keyInfoGenerator.generate(credential);

    KeyName keyName = buildSAMLObject(KeyName.class, KeyName.DEFAULT_ELEMENT_NAME);
    keyName.setValue(proxyKeyName);

    keyInfo.getKeyNames().add(keyName);
    encKeyDescriptor.setKeyInfo(keyInfo);

    idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

    entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSignMetadata(true);
    extendedMetadata.setSigningAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSigningKey(entityId);
    extendedMetadata.setLocal(true);

    return SAMLUtil.getMetadataAsString(metadataManager, keyManager, entityDescriptor, extendedMetadata);

  }

  private String writeEntityDescriptor(EntityDescriptor entityDescriptor) throws ParserConfigurationException, MarshallingException, TransformerException {
    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(entityDescriptor);
    Element element = marshaller.marshall(entityDescriptor);
    return XMLHelper.nodeToString(element);
  }

}
