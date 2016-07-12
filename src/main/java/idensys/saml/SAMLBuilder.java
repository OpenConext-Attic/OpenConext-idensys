package idensys.saml;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

public class SAMLBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(SAMLBuilder.class);

  private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

  @SuppressWarnings({"unused", "unchecked"})
  public static <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
    return (T) builderFactory.getBuilder(qName).buildObject(qName);
  }

  public static Issuer buildIssuer(String issuingEntityName) {
    Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(issuingEntityName);
    issuer.setFormat(NameIDType.ENTITY);
    return issuer;
  }

  public static Subject buildSubject(String subjectNameId, String subjectNameIdType, String recipient, String inResponseTo) {
    NameID nameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
    nameID.setValue(subjectNameId);
    nameID.setFormat(subjectNameIdType);

    Subject subject = buildSAMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
    subject.setNameID(nameID);

    SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

    SubjectConfirmationData subjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class, SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

    subjectConfirmationData.setRecipient(recipient);
    subjectConfirmationData.setInResponseTo(inResponseTo);
    subjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(8 * 60));
    subjectConfirmationData.setAddress(recipient);

    subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

    subject.getSubjectConfirmations().add(subjectConfirmation);

    return subject;
  }

  public static Status buildStatus(String value) {
    Status status = buildSAMLObject(Status.class, Status.DEFAULT_ELEMENT_NAME);
    StatusCode statusCode = buildSAMLObject(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(value);
    status.setStatusCode(statusCode);
    return status;
  }

  public static Status buildStatus(String value, String subStatus, String message) {
    Status status = buildStatus(value);

    StatusCode subStatusCode = buildSAMLObject(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
    subStatusCode.setValue(subStatus);
    status.getStatusCode().setStatusCode(subStatusCode);

    StatusMessage statusMessage = buildSAMLObject(StatusMessage.class, StatusMessage.DEFAULT_ELEMENT_NAME);
    statusMessage.setMessage(message);
    status.setStatusMessage(statusMessage);

    return status;
  }

  public static Assertion buildAssertion(SAMLPrincipal principal, Status status, String entityId) {
    Assertion assertion = buildSAMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);

    if (status.getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
      Subject subject = buildSubject(principal.getNameID(), principal.getNameIDType(), principal.getAssertionConsumerServiceURL(), principal.getRequestID());
      assertion.setSubject(subject);
    }

    Issuer issuer = buildIssuer(entityId);

    Audience audience = buildSAMLObject(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
    audience.setAudienceURI(principal.getServiceProviderEntityID());
    AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class, AudienceRestriction.DEFAULT_ELEMENT_NAME);
    audienceRestriction.getAudiences().add(audience);

    Conditions conditions = buildSAMLObject(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
    conditions.getAudienceRestrictions().add(audienceRestriction);
    assertion.setConditions(conditions);

    AuthnStatement authnStatement = buildAuthnStatement(new DateTime(), entityId);

    assertion.setIssuer(issuer);
    assertion.getAuthnStatements().add(authnStatement);

    assertion.getAttributeStatements().add(buildAttributeStatement(principal.getAttributes()));

    assertion.setID(UUID.randomUUID().toString());
    assertion.setIssueInstant(new DateTime());

    return assertion;
  }

  public static void signAssertion(SignableXMLObject signableXMLObject, Credential signingCredential) throws MarshallingException, SignatureException {
    Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

    signableXMLObject.setSignature(signature);

    Configuration.getMarshallerFactory().getMarshaller(signableXMLObject).marshall(signableXMLObject);
    Signer.signObject(signature);
  }

  public static Optional<String> getStringValueFromXMLObject(XMLObject xmlObj, SAMLMessageContext context) {
    if (xmlObj instanceof XSString) {
      return Optional.of(((XSString) xmlObj).getValue());
    } else if (xmlObj instanceof XSAny) {
      XSAny xsAny = (XSAny) xmlObj;
      String textContent = xsAny.getTextContent();
      if (StringUtils.hasText(textContent)) {
        return Optional.of(textContent);
      }
      List<XMLObject> unknownXMLObjects = xsAny.getUnknownXMLObjects();
      if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
        XMLObject xmlObject = unknownXMLObjects.get(0);
        if (xmlObject instanceof NameID) {
          NameID nameID = (NameID) xmlObject;
          return Optional.of(nameID.getValue());
        } else if (xmlObject instanceof EncryptedID) {
          EncryptedID encrypted = (EncryptedID) xmlObject;
          Decrypter decrypter = context.getLocalDecrypter();
          try {
            SAMLObject samlObject = decrypter.decrypt(encrypted);
            if (samlObject instanceof NameID) {
              NameID nameID = (NameID) samlObject;
              return Optional.of(nameID.getValue());
            }
          } catch (DecryptionException e) {
            throw new RuntimeException(e);
          }
        }
      }
    }
    return Optional.empty();
  }

  private static AuthnStatement buildAuthnStatement(DateTime authnInstant, String entityID) {
    AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

    AuthenticatingAuthority authenticatingAuthority = buildSAMLObject(AuthenticatingAuthority.class, AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
    authenticatingAuthority.setURI(entityID);

    AuthnContext authnContext = buildSAMLObject(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);
    authnContext.setAuthnContextClassRef(authnContextClassRef);
    authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);

    AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);
    authnStatement.setAuthnContext(authnContext);

    authnStatement.setAuthnInstant(authnInstant);

    return authnStatement;

  }

  private static AttributeStatement buildAttributeStatement(List<SAMLAttribute> attributes) {
    AttributeStatement attributeStatement = buildSAMLObject(AttributeStatement.class, AttributeStatement.DEFAULT_ELEMENT_NAME);

    attributes.forEach(entry ->
      attributeStatement.getAttributes().add(
        buildAttribute(
          entry.getName(),
          entry.getValues().stream().map(SAMLBuilder::buildAttributeValue).collect(toList()))));

    return attributeStatement;
  }

  private static Attribute buildAttribute(String name, List<XSString> values) {
    Attribute attribute = buildSAMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
    attribute.setName(name);
    attribute.getAttributeValues().addAll(values);
    return attribute;
  }

  private static XSString buildAttributeValue(String value) {
    XSStringBuilder stringBuilder = new XSStringBuilder();
    //we need an AttributeValue and not a XSString and this is how it works apparently - there is no AttributeValueBuilder
    XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
    attributeValue.setValue(value);
    return attributeValue;
  }

}
