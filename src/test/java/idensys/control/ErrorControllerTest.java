package idensys.control;

import org.junit.Test;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestAttributes;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class ErrorControllerTest {

  @Test
  public void testError() throws Exception {
    ErrorAttributes errorAttributes = mock(ErrorAttributes.class);
    ErrorController subject = new ErrorController(errorAttributes, null);

    when(errorAttributes.getError(any(RequestAttributes.class))).thenReturn(null);

    MockHttpServletResponse response = new MockHttpServletResponse();
    subject.error(new MockHttpServletRequest(), response);

    assertEquals(403, response.getStatus());
    assertTrue(response.isCommitted());
  }
}
