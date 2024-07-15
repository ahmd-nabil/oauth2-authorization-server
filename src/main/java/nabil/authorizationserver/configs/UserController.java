package nabil.authorizationserver.configs;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * @author Ahmed Nabil
 */
@RestController
public class UserController {

    // resource
    @GetMapping("/appUser")
    Map<String, Object> user(Authentication authentication) {
        return Collections.singletonMap("sub", authentication.getName());
    }
}
