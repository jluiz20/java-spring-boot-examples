package xyz.joaovieira.security.resourceserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sample class that is used for validating the Security Config, not for production usage
 */
@RestController
public class DummyController {

    /**
     * returns the principal used for the authentication for us to be able to check the principal used
     */
    @GetMapping(value = "/api/secure")
    public String secureEndpoint() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return objectMapper.writeValueAsString(principal);
    }

    @GetMapping("/api/public")
    public String publicEndpoint() {
        return "Public endpoint accessed";
    }

    @PostMapping("/api/user/{userId}/invite")
    public String publicEndpoint(@PathVariable String userId) {
        return "Public endpoint accessed";
    }
}
