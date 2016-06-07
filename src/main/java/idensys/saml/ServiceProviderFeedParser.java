package idensys.saml;

import org.springframework.core.io.Resource;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;

public class ServiceProviderFeedParser {

  private final Resource resource;

  public ServiceProviderFeedParser(Resource resource) {
    this.resource = resource;
  }

  public Map<String, ServiceProvider> parse() throws IOException, XMLStreamException {
    //despite it's name, the XMLInputFactoryImpl is not thread safe
    XMLInputFactory factory = XMLInputFactory.newInstance();

    XMLStreamReader reader = factory.createXMLStreamReader(resource.getInputStream());

    Map<String, ServiceProvider> serviceProviders = new HashMap<>();

    String entityId = null, signingCertificate = null;
    boolean isServiceProvider = false, isSigning = false;
    List<String> assertionConsumerServiceURLs = null;

    while (reader.hasNext()) {
      switch (reader.next()) {
        case START_ELEMENT:
          switch (reader.getLocalName()) {
            case "EntityDescriptor":
              entityId = reader.getAttributeValue(null, "entityID");
              break;
            case "SPSSODescriptor":
              isServiceProvider = true;
              break;
            case "KeyDescriptor":
              isSigning = "signing".equals(reader.getAttributeValue(null, "use"));
              break;
            case "X509Certificate":
              if (isServiceProvider && isSigning) {
                signingCertificate = reader.getElementText().replaceAll("\\s", "");
              }
              break;
            case "AssertionConsumerService":
              if (assertionConsumerServiceURLs == null) {
                assertionConsumerServiceURLs = new ArrayList<>();
              }
              assertionConsumerServiceURLs.add(reader.getAttributeValue(null, "Location"));
              break;
          }
          break;
        case END_ELEMENT:
          if (reader.getLocalName().equals("EntityDescriptor") && isServiceProvider) {
            serviceProviders.put(entityId, new ServiceProvider(entityId, signingCertificate, assertionConsumerServiceURLs));
            entityId = null;
            signingCertificate = null;
            isServiceProvider = false;
            isSigning = false;
            assertionConsumerServiceURLs = null;
          }
          break;
      }
    }
    return serviceProviders;
  }

}
