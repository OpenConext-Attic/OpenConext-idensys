package idensys.control;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.key.KeyManager;
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

  @Value("${proxy.entity_id}")
  private String entityId;

  @Value("${proxy.validity_duration_metadata_ms}")
  private int validityDurationMetadataMilliseconds;

  @RequestMapping(method = RequestMethod.GET, value = "/idp/metadata", produces = "application/xml")
  public String metadata() throws SecurityException, ParserConfigurationException, SignatureException, MarshallingException, TransformerException {
    if (metadata == null || this.validUntil.isBeforeNow()) {
      this.metadata = generateMetadata();
    }
    return this.metadata;
  }

  private String generateMetadata() throws SecurityException, SignatureException, MarshallingException, ParserConfigurationException, TransformerException {
    this.validUntil = new DateTime().plusMillis(validityDurationMetadataMilliseconds);

    EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
    entityDescriptor.setEntityID(entityId);
    entityDescriptor.setID(UUID.randomUUID().toString());
    entityDescriptor.setValidUntil(this.validUntil);

    Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

    Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
    signature.setSigningCredential(credential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

    entityDescriptor.setSignature(signature);

    Configuration.getMarshallerFactory().getMarshaller(entityDescriptor).marshall(entityDescriptor);
    Signer.signObject(signature);

    IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

    NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
    nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    idpssoDescriptor.getNameIDFormats().add(nameIDFormat);

    idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

    X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    keyInfoGeneratorFactory.setEmitEntityCertificate(true);
    KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

    KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
    encKeyDescriptor.setUse(UsageType.SIGNING);

    encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));

    idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

    entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

    return writeEntityDescriptor(entityDescriptor);
  }

  private String writeEntityDescriptor(EntityDescriptor entityDescriptor) throws ParserConfigurationException, MarshallingException, TransformerException {
    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(entityDescriptor);
    Element element = marshaller.marshall(entityDescriptor);
    return XMLHelper.nodeToString(element);
  }

}
