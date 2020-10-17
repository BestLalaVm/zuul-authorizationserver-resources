package saas.resourceserver.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import saas.resourceserver.responses.UserResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class ResourceController {
    @GetMapping("/user/{username}")
    public UserResponse get(HttpServletRequest req, HttpServletResponse resp, @PathVariable("username") String username) {
        if (req.getHeader("trackId") != null) {
            resp.addHeader("trackId", req.getHeader("trackId"));
        } else {
            resp.addHeader("trackId", "None");
        }

        return new UserResponse(username);
    }
}
