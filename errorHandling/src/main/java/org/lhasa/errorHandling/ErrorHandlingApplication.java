package org.lhasa.errorHandling;


import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

@SpringBootApplication
@EnableWebMvc
public class ErrorHandlingApplication {

    @Bean
    UserDetailsManager userDetailService() {
        return new InMemoryUserDetailsManager();
    }

    @Bean
    InitializingBean initializingBean(@Qualifier("userDetailService") UserDetailsManager udm, DispatcherServlet ds) {
        return () ->
        {
            udm.createUser(User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build());
            udm.createUser(User.withDefaultPasswordEncoder().username("admin").password("admin").roles("ADMIN").build());
            ds.setThrowExceptionIfNoHandlerFound(true);
        };
    }

    public static void main(String[] args) {
        SpringApplication.run(ErrorHandlingApplication.class, args);
    }

}

@RestController
class TestController {

    @GetMapping("/getIntegerTest/{testValue}")
    public String getIntegerTest(@PathVariable("testValue") Integer test) {
        return "getTest " + test;
    }

    @PostMapping("validTest")
    public String validationTest(@Valid @RequestBody ValidationTest vt) {

        return vt.email;
    }
}

class ValidationTest {
    @Max(100)
    @Min(10)
    Integer size;

    @NotBlank
    @Email
    String email;

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

@ControllerAdvice
//(annotations = RestController.class)
class TestExceptionHandler {

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<String> requestHandlingNoHandlerFound(NoHandlerFoundException e) {
        return new ResponseEntity<>("NoHandlerFoundException custom message example\n\n" + e.getLocalizedMessage(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler
    public ResponseEntity<String> customHandlerMethodArg(MethodArgumentTypeMismatchException e) {
        String message = "MethodArgumentTypeMismatchException custom message example\n" + e.getLocalizedMessage();
        return ResponseEntity.badRequest().body(message);
    }

    @ExceptionHandler
    public ResponseEntity<String> customHandlerMethodArg(HttpRequestMethodNotSupportedException e) {
        String message = "HttpRequestMethodNotSupportedException custom message example\n\n" + e.getLocalizedMessage();
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(message);
    }

    @ExceptionHandler
    public ResponseEntity<String> customHandlerMethodArg(MethodArgumentNotValidException e) {
        String message = "MethodArgumentNotValidException custom message example\n\n" + e.getLocalizedMessage();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST) .body(message);
    }

    @ExceptionHandler
    public ResponseEntity<String> customHandler(Exception e) {
        String message = "Any unhandled exception custom message example...\n" + e;
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(message);
    }

//    @ExceptionHandler
//    public ResponseEntity<String> customHandler(AccessDeniedException e) {
//        String message = "AccessDeniedException exception custom message example...\n" + e;
//        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(message);
//    }
}

@Configuration
@EnableWebSecurity
class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().httpBasic().and()
                .authorizeRequests()
                .mvcMatchers(HttpMethod.POST, "**").permitAll()
                .anyRequest().authenticated();
    }

}