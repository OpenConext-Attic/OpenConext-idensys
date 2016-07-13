package idensys.saml;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static idensys.saml.SAMLBuilder.buildSAMLObject;

public class CustomHTTPSOAP11Encoder extends org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder {

  private final String credentialKeyName;

  private static final Logger LOG = LoggerFactory.getLogger(CustomHTTPSOAP11Encoder.class);

  public CustomHTTPSOAP11Encoder(String credentialKeyName) {
    this.credentialKeyName = credentialKeyName;
  }

  /**
   * Nasty Hack to ensure we don't get the X509 in the keyInfo element of the signature. When we call
   * super.sign we are too late, as the Signature can not be changed then (see releaseDom in SignatureImpl).
   *
   * Even if we use Java reflection we can't change it, as all the nodes are linked together.
   *
   */
  @Override
  protected void signMessage(SAMLMessageContext messageContext) throws MessageEncodingException {
    SAMLObject outboundSAML = messageContext.getOutboundSAMLMessage();
    Credential signingCredential = messageContext.getOuboundSAMLMessageSigningCredential();

    if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
      SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

      XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
        Signature.DEFAULT_ELEMENT_NAME);
      Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

      signature.setSigningCredential(signingCredential);
      KeyInfo keyInfo = buildSAMLObject(KeyInfo.class, KeyInfo.DEFAULT_ELEMENT_NAME);
      KeyName keyName = buildSAMLObject(KeyName.class, KeyName.DEFAULT_ELEMENT_NAME);
      keyName.setValue(credentialKeyName);
      keyInfo.getKeyNames().add(keyName);
      signature.setKeyInfo(keyInfo);
      try {
        SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
      } catch (SecurityException e) {
        throw new MessageEncodingException("Error preparing signature for signing", e);
      }

      signableMessage.setSignature(signature);

      try {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
        if (marshaller == null) {
          throw new MessageEncodingException("No marshaller registered for "
            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
        }
        marshaller.marshall(signableMessage);

        Signer.signObject(signature);
      } catch (MarshallingException e) {
        LOG.error("Unable to marshall protocol message in preparation for signing", e);
        throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
      } catch (SignatureException e) {
        LOG.error("Unable to sign protocol message", e);
        throw new MessageEncodingException("Unable to sign protocol message", e);
      }
    }
  }
}

