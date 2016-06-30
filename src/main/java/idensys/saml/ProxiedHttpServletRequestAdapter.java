package idensys.saml;

import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import javax.servlet.http.HttpServletRequest;

public class ProxiedHttpServletRequestAdapter extends HttpServletRequestAdapter {
  /**
   * Constructor.
   *
   * @param request servlet request to adap
   */
  public ProxiedHttpServletRequestAdapter(HttpServletRequest request) {
    super(request);
  }


}
