package idensys;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactBuilder;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoderImpl;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml.key.KeyManager;

import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;

import static idensys.saml.SAMLBuilder.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLRequestUtils {

  private final KeyManager keyManager;

  public SAMLRequestUtils(KeyManager keyManager) {
    this.keyManager = keyManager;
  }

  /*
   * The OpenSAML API is very verbose..
   */
  @SuppressWarnings("unchecked")
  public String redirectUrl(String entityId, String destination, String acs, Optional<String> userId, boolean includeSignature)
      throws SecurityException, MessageEncodingException, SignatureException, MarshallingException, UnknownHostException {
    AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID(UUID.randomUUID().toString());
    authnRequest.setIssueInstant(new DateTime());
    authnRequest.setDestination(destination);
    authnRequest.setAssertionConsumerServiceURL(acs);

    authnRequest.setIssuer(buildIssuer(entityId));

    Credential signingCredential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));

    boolean includeSigning = includeSignature && signingCredential.getPrivateKey() != null;
    if (includeSigning) {
      signAssertion(authnRequest, signingCredential);
    }

    Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    endpoint.setLocation(destination);

    MockHttpServletResponse response = new MockHttpServletResponse();
    HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder() {
      @Override
      protected void removeSignature(SAMLMessageContext messageContext) {
        if (!includeSignature) {
          super.removeSignature(messageContext);
        }
      }
    };

    BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

    messageContext.setOutboundMessageTransport(outTransport);
    messageContext.setPeerEntityEndpoint(endpoint);
    messageContext.setOutboundSAMLMessage(authnRequest);

    if (includeSigning) {
      messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);
    }

    messageContext.setRelayState(null);

    encoder.encode(messageContext);
    return response.getRedirectedUrl();
  }

  public String signFile(Resource xmlResource) throws Exception {
    Init.init();

    Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlResource.getInputStream());
    ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");
    XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA);
    Transforms transforms = new Transforms(doc);
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
    sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

    Credential credential = keyManager.getCredential("https://idensys.localhost.surfconext.nl");

    Key privateKey = credential.getPrivateKey();
    X509Certificate certificate = keyManager.getCertificate("https://idensys.localhost.surfconext.nl");
    sig.addKeyInfo(certificate);
    sig.addKeyInfo(certificate.getPublicKey());
    sig.sign(privateKey);
    doc.getDocumentElement().appendChild(sig.getElement());
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS).canonicalizeSubtree(doc));
    return outputStream.toString();
  }

  public String artifact(MetadataManager metadataManager, String entityId) throws MetadataProviderException {
    SAMLMessageContext requestContext = mock(SAMLMessageContext.class);

    RoleDescriptor role = metadataManager.getRole(entityId, new QName("urn:oasis:names:tc:SAML:2.0:metadata", "IDPSSODescriptor", "md"), SAMLConstants.SAML20P_NS);

    when(requestContext.getLocalEntityRoleMetadata()).thenReturn(role);
    when(requestContext.getLocalEntityId()).thenReturn(entityId);
    when(requestContext.getLocalEntityMetadata()).thenReturn(metadataManager.getEntityDescriptor(entityId));
    when(requestContext.getMetadataProvider()).thenReturn(metadataManager);

    SAML2ArtifactBuilder artifactBuilder = Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(SAML2ArtifactType0004.TYPE_CODE);
    requestContext.setOutboundMessageArtifactType(SAML2ArtifactType0004.TYPE_CODE);
    AbstractSAML2Artifact artifact = artifactBuilder.buildArtifact(requestContext);
    return artifact.base64Encode();
  }

}
