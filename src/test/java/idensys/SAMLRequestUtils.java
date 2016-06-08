package idensys;

import org.joda.time.DateTime;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml.key.KeyManager;

import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;

import static idensys.saml.SAMLBuilder.*;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Document;

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

}
