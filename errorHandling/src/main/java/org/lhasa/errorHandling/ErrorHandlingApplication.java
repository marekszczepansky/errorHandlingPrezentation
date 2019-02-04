package org.lhasa.errorHandling;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableWebMvc
public class ErrorHandlingApplication
{
	@Bean
	UserDetailsManager userDetailService()
	{
		return new InMemoryUserDetailsManager();
	}

	@Bean
	InitializingBean initializingBean(@Qualifier("userDetailService") UserDetailsManager udm, DispatcherServlet ds)
	{
		return () ->
		{
			udm.createUser(User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build());
			udm.createUser(User.withDefaultPasswordEncoder().username("admin").password("admin").roles("ADMIN").build());
			ds.setThrowExceptionIfNoHandlerFound(true);
		};
	}

	public static void main(String[] args)
	{
		SpringApplication.run(ErrorHandlingApplication.class, args);
	}
}

@RestController
class TestController
{
	@GetMapping(value = "/getIntegerTest/{testValue}")
	public String getIntegerTest(@PathVariable("testValue") Integer test)
	{
		return "getTest " + test;
	}

	@PostMapping("validTest")
	public String validationTest(@Valid @RequestBody ValidationTest vt)
	{
		return "Valid email: " + vt.email;
	}

	@GetMapping("test204")
	@ResponseStatus(value = HttpStatus.NO_CONTENT, reason = "there is no content :)")
	public void test204()
	{
	}
}

@ControllerAdvice
class TestExceptionHandler
{
	@ExceptionHandler
	public ResponseEntity<String> customHandlerMethodArg(MethodArgumentTypeMismatchException e)
	{
		String message = "MethodArgumentTypeMismatchException custom message example\n" + e.getLocalizedMessage();
		return ResponseEntity.badRequest().body(message);
	}

	@ExceptionHandler
	public ResponseEntity<String> customHandlerMethodArg(HttpMessageNotReadableException e)
	{
		String message = "HttpMessageNotReadableException custom message example\n" + e.getLocalizedMessage();
		return ResponseEntity.badRequest().body(message);
	}

	@ExceptionHandler
	public ResponseEntity<String> customHandlerMethodArg(MethodArgumentNotValidException e)
	{
		String message = "MethodArgumentNotValidException custom message example\n\n" + e.getBindingResult();
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
	}

	@ExceptionHandler
	public ResponseEntity<String> customHandlerMethodArg(HttpRequestMethodNotSupportedException e)
	{
		String message = "HttpRequestMethodNotSupportedException custom message example\n\n" + e.getLocalizedMessage();
		return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(message);
	}

	@ExceptionHandler
	public ResponseEntity<String> customHandlerMethodArg(NumberFormatException e)
	{
		String message = "NumberFormatException custom message example\n\n" + e.getLocalizedMessage();
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
	}

	@ExceptionHandler(NoHandlerFoundException.class)
	public ResponseEntity<String> requestHandlingNoHandlerFound(NoHandlerFoundException e)
	{
		return new ResponseEntity<>(
				"NoHandlerFoundException custom message example\n\n" + e.getLocalizedMessage(),
				HttpStatus.NOT_FOUND
		);
	}
}

class ValidationTest
{
	@Max(value = 100, message = "Custom max limit message !!!!!!!!!!!!!!!!!!!!!!!!!!!")
	@Min(10)
	Integer size;

	@NotBlank
	@Email(message = "CUSTOM not valid email message!!!!!!!!!!!!!!!!!!!!!!!")
	String email;

	public Integer getSize()
	{
		return size;
	}

	public void setSize(Integer size)
	{
		this.size = size;
	}

	public String getEmail()
	{
		return email;
	}

	public void setEmail(String email)
	{
		this.email = email;
	}
}

@RestController
class AnyExceptionHandlerLimit
{
	@GetMapping("test500")
	public void test500()
	{
		throw new ArrayIndexOutOfBoundsException(-1);
	}
}

@ControllerAdvice(assignableTypes = AnyExceptionHandlerLimit.class)
class TestControllerOnlyAdvice
{
	@ExceptionHandler
	public ResponseEntity<String> customHandler(Exception e)
	{
		String message = "Any unhandled exception custom message example...\n" + e.getLocalizedMessage();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(message);
	}
}

@RestController
class SerurityTest
{
	@GetMapping("/forAdmin")
	public String forAdmin()
	{
		return "Hello admin :)";
	}
}

@Configuration
@EnableWebSecurity
class WebSecurityConfiguration extends WebSecurityConfigurerAdapter
{
	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		http
				.csrf().disable()
				.httpBasic().and()
				.exceptionHandling()
				.accessDeniedHandler((request, response, ex) ->
						response.sendError(403, "this is custom 403 handler"))
				.authenticationEntryPoint((request, response, ex) ->
				{
					//	response.sendError(404, "{\"message\": \"This is custom 401 handler :(\"}");
					response.setStatus(401);
					response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
					response.getOutputStream().println("{\"message\": \"This is custom 401 handler :(\"}");
				})
				.and()
				.authorizeRequests()
				.mvcMatchers("/forAdmin").hasRole("ADMIN")
				.mvcMatchers(HttpMethod.POST, "**").permitAll()
				.anyRequest().authenticated();
	}
}

@RestController
class ServiceTest
{
	@Autowired ITestService testService;

	@GetMapping("/service404/{id}")
	String service404(@PathVariable("id") Integer id)
	{
		return testService.rise404();
	}

	@GetMapping("/service403")
	String service403()
	{
		return testService.rise403();
	}
}

@Service
class TestService implements ITestService
{
	@Override
	public String rise404()
	{
		throw new StudyNotFound();
	}

	@Override
	public String rise403()
	{
		throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You shall not pass!");
	}
}

@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Study does not exists")
class StudyNotFound extends RuntimeException
{
	@Override
	public synchronized Throwable fillInStackTrace()
	{
		return this;
	}
}