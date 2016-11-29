package ulcambridge.foundations.viewer.authentication.distributed;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.util.UriComponentsBuilder;
import ulcambridge.foundations.viewer.utils.Utils;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;

@Controller
@RequestMapping("/auth")
public class AuthTokenController {

    /** The mime type for JSON web tokens. */
    private static final String APPLICATION_JWT_STR = "application/jwt";

    private final URI issuerUrl;
    private final JwtCreator jwtCreator;

    @Autowired
    public AuthTokenController(
        @Qualifier("homepageUrl") URI issuerUrl, JwtCreator jwtCreator) {

        Assert.notNull(issuerUrl);
        Assert.notNull(jwtCreator);

        this.issuerUrl = issuerUrl;
        this.jwtCreator = jwtCreator;
    }

    /**
     * Create a JSON Web Token to delegate the authenticated user's
     * authorisation(s) to another CUDL service.
     */
    @RequestMapping(path = "/token", method = RequestMethod.POST,
                    produces = APPLICATION_JWT_STR)
    @ResponseBody
    @PreAuthorize("isAuthenticated()")
    public String createJsonWebToken(
        @RequestParam URI audience, @RequestParam Optional<Duration> lifetime,
        HttpServletRequest request)
        throws TokenException {

        return this.jwtCreator.createJwt(
            getIssuerUrl(request), audience, getUsername(), lifetime);
    }

    private String getUsername() {
        Object principal = SecurityContextHolder.getContext()
            .getAuthentication().getPrincipal();

        if(!(principal instanceof UserDetails))
            throw new RuntimeException(
                "Principal was not a UserDetails instance");

        return ((UserDetails)principal).getUsername();
    }

    private URI getIssuerUrl(HttpServletRequest request) {
        if(this.issuerUrl.isAbsolute())
            return this.issuerUrl;

        return Utils.populateScheme(
            UriComponentsBuilder.fromUri(this.issuerUrl), request)
            .build().toUri();
    }

    @ResponseStatus(code = HttpStatus.FORBIDDEN)
    @ResponseBody
    @ExceptionHandler
    public String badAudienceUrl(TokenException e) {
        return e.getMessage();
    }

    @ResponseStatus(code = HttpStatus.BAD_REQUEST)
    @ResponseBody
    @ExceptionHandler
    public String invalidRequestParam(MethodArgumentTypeMismatchException e) {
        return String.format(
            "Parameter \"%s\" was invalid: %s",
            e.getParameter().getParameterName(),
            e.getMostSpecificCause().getMessage());
    }
}
