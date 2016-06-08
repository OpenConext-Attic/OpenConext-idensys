package idensys.control;

import org.apache.commons.io.IOUtils;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;

@RestController
public class ServiceCatalogController {

  @RequestMapping(method = RequestMethod.GET, value = "/service/catalog", produces = "application/xml")
  public String serviceCatalog() throws IOException {
    return IOUtils.toString(new ClassPathResource("service_catalog.xml").getInputStream());
  }


}
