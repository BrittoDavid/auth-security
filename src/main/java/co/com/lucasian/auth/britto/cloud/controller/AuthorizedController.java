package co.com.lucasian.auth.britto.cloud.controller;

import java.util.Collections;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author DavidBritto
 */
@RestController
@RequestMapping("/authorized")
public class AuthorizedController {
    
    @GetMapping
    public Map<String, Object> authorized(@RequestParam(name = "code") String code) {
        return Collections.singletonMap("code", code);
    }
    
}
