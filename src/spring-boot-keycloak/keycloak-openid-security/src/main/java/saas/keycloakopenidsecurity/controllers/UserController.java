package saas.keycloakopenidsecurity.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/users")
public class UserController {
    @GetMapping("/{name}")
    public String get(@PathVariable("name") String name, HttpServletRequest request) {
        return "Hello," + name + "," + request.getUserPrincipal();
    }
}
