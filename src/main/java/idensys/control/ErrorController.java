package idensys.control;

import idensys.saml.SAMLAuthenticationException;
import idensys.saml.SAMLMessageHandler;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
public class ErrorController implements org.springframework.boot.autoconfigure.web.ErrorController {

  private final ErrorAttributes errorAttributes;
  private final SAMLMessageHandler samlMessageHandler;

  @Autowired
  public ErrorController(ErrorAttributes errorAttributes, SAMLMessageHandler samlMessageHandler) {
    Assert.notNull(errorAttributes, "ErrorAttributes must not be null");
    this.errorAttributes = errorAttributes;
    this.samlMessageHandler = samlMessageHandler;
  }

  @Override
  public String getErrorPath() {
    return "/error";
  }

  @RequestMapping("/error")
  public void error(HttpServletRequest request, HttpServletResponse response) throws IOException, MarshallingException, SignatureException, MessageEncodingException {
    RequestAttributes requestAttributes = new ServletRequestAttributes(request);
    Throwable error = this.errorAttributes.getError(requestAttributes);
    if (error instanceof SAMLAuthenticationException) {
      samlMessageHandler.sendFailedAuthnResponse((SAMLAuthenticationException) error, response);
    } else {
      response.sendError(FORBIDDEN.value());
    }
  }

}
