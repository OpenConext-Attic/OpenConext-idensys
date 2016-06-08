package idensys;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
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
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;

import static idensys.saml.SAMLBuilder.*;

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

    if (userId.isPresent()) {
      Subject subject = buildSubject(userId.get(), NameID.UNSPECIFIED, "http://localhost:8080", UUID.randomUUID().toString());
      authnRequest.setSubject(subject);
    }

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

  public String artifactResolve(String destination, String entityId, String artifactValue) throws SecurityException, MarshallingException, SignatureException, TransformerException, ParserConfigurationException {
    ArtifactResolve artifactResolve = buildSAMLObject(ArtifactResolve.class, ArtifactResolve.DEFAULT_ELEMENT_NAME);
    artifactResolve.setID(UUID.randomUUID().toString());
    artifactResolve.setIssueInstant(new DateTime());
    artifactResolve.setDestination(destination);
    artifactResolve.setIssuer(buildIssuer(entityId));


    Artifact artifact = buildSAMLObject(Artifact.class, Artifact.DEFAULT_ELEMENT_NAME);
    artifact.setArtifact(artifactValue);
    artifactResolve.setArtifact(artifact);

//    TODO: if we want to sign this then we need the private key of the IdP which we would only need for testing purposes
//    Credential signingCredential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
//    signAssertion(artifactResolve, signingCredential);
    Envelope envelope = buildSAMLObject(Envelope.class, Envelope.DEFAULT_ELEMENT_NAME);

    Body body = buildSAMLObject(Body.class, Body.DEFAULT_ELEMENT_NAME);
    body.getUnknownXMLObjects().add(artifactResolve);

    envelope.setBody(body);
    return writeXMLObject(envelope);

  }

  private String writeXMLObject(XMLObject xmlObject) throws ParserConfigurationException, MarshallingException, TransformerException {
    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
    Element element = marshaller.marshall(xmlObject);
    return XMLHelper.nodeToString(element);
  }

}
