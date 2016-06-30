package idensys.saml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class ParameterDecodingHttpServletRequestWrapper extends HttpServletRequestWrapper {

  public ParameterDecodingHttpServletRequestWrapper(HttpServletRequest request) {
    super(request);
  }

  @Override
  public String getParameter(String name) {
    String parameter = super.getParameter(name);
    return parameter != null ? decode(parameter) : null;
  }

  private String decode(String parameter) {
    try {
      return URLDecoder.decode(parameter, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }


}
