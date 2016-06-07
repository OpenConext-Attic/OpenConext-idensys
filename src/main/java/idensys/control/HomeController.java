package idensys.control;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

  @RequestMapping(path = {"/user", "/test"})
  public String user(Authentication authentication, ModelMap modelMap) {
    modelMap.addAttribute("user", authentication.getPrincipal());
    return "user";
  }
}
