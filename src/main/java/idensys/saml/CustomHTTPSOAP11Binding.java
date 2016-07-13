package idensys.saml;

import org.opensaml.saml2.binding.decoding.HTTPSOAP11DecoderImpl;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;

public class CustomHTTPSOAP11Binding extends HTTPSOAP11Binding {

  public CustomHTTPSOAP11Binding(ParserPool parserPool, String credentialKeyName) {
    super(new HTTPSOAP11DecoderImpl(parserPool), new CustomHTTPSOAP11Encoder(credentialKeyName));
  }
}
