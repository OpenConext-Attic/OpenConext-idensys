package idensys.saml;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * SAMLPrincipal holds all the - minimal -information to send an SAML AuthnResponse back to the
 * SP.
 */
public class SAMLPrincipal implements Principal {

  private final String serviceProviderEntityID;
  private final String requestID;
  private final String assertionConsumerServiceURL;
  private final String relayState;
  private final List<SAMLAttribute> attributes = new ArrayList<>();

  private String nameID;
  private String nameIDType;

  public SAMLPrincipal(String serviceProviderEntityID, String requestID, String assertionConsumerServiceURL, String relayState) {
    this.serviceProviderEntityID = serviceProviderEntityID;
    this.requestID = requestID;
    this.assertionConsumerServiceURL = assertionConsumerServiceURL;
    this.relayState = relayState;
  }

  public void elevate(String nameID, String nameIDType, List<SAMLAttribute> attributes) {
    this.nameID = nameID;
    this.nameIDType = nameIDType;
    this.attributes.addAll(attributes);
  }

  public String getServiceProviderEntityID() {
    return serviceProviderEntityID;
  }

  public String getRequestID() {
    return requestID;
  }

  public String getAssertionConsumerServiceURL() {
    return assertionConsumerServiceURL;
  }

  public String getRelayState() {
    return relayState;
  }

  public List<SAMLAttribute> getAttributes() {
    return attributes;
  }

  public String getNameID() {
    return nameID;
  }

  public String getNameIDType() {
    return nameIDType;
  }

  @Override
  public String getName() {
    return nameID;
  }

  @Override
  public String toString() {
    return "SAMLPrincipal{" +
      "attributes=" + attributes +
      ", serviceProviderEntityID='" + serviceProviderEntityID + '\'' +
      ", requestID='" + requestID + '\'' +
      ", assertionConsumerServiceURL='" + assertionConsumerServiceURL + '\'' +
      ", nameID='" + nameID + '\'' +
      ", relayState='" + relayState + '\'' +
      '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    SAMLPrincipal that = (SAMLPrincipal) o;
    return Objects.equals(nameID, that.nameID);
  }

  @Override
  public int hashCode() {
    return Objects.hash(nameID);
  }
}
