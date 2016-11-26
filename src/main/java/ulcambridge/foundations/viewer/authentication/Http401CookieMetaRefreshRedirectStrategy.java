package ulcambridge.foundations.viewer.authentication;

import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static ulcambridge.foundations.viewer.utils.JavascriptUtils.createJavascriptString;

/**
 * A {@link RedirectStrategy} intended for use with an
 * {@link AuthenticationEntryPoint} to send redirects which can be handled by a
 * browser, and understood by a non-interactive agent, or AJAX request handler.
 *
 * <p>We send a 401 unauthorised response, which can be understood by ajax
 * requests and other non-interactive clients. We also set a Refresh header,
 * which although non-standard, is understood by seemingly every browser since
 * Netscape.
 */
public class Http401CookieMetaRefreshRedirectStrategy
    implements RedirectStrategy {

    public static final String DEFAULT_COOKIE_NAME = "JSESSIONID";

    private final String cookieName;

    public Http401CookieMetaRefreshRedirectStrategy() {
        this(DEFAULT_COOKIE_NAME);
    }

    public Http401CookieMetaRefreshRedirectStrategy(String cookieName) {
        Assert.hasText(cookieName);

        this.cookieName = cookieName;
    }

    private static final String escapeAuthenticateHeaderToken(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String renderHtmlResponse(String url) {
        String escapedUrl = HtmlUtils.htmlEscape(url);
        String jsonEncodedUrl = createJavascriptString(url);

        return "<!DOCTYPE html>" +
            // In case the Refresh header is not handled
            "<meta http-equiv=\"refresh\" content=\"0; url=" + escapedUrl + "\">" +
            // In case the meta refresh is not handled
            "<script>window.location = " + jsonEncodedUrl + ";</script>" +
            "<title>Log in required</title>" +
            // If all else fails, provide a link to the login page
            "<h1>Log in required</h1>" +
            "<p>" +
                "You need to log in but your browser didn't automatically " +
                "redirect you. <a href=\"" + escapedUrl + "\">Click here</a> " +
                "to log in." +
            "</p>";
    }

    @Override
    public void sendRedirect(
        HttpServletRequest request, HttpServletResponse response, String url)
        throws IOException {

        // Send a 401 status code which can be understood by non-interactive
        // clients.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        // With 401 a WWW-Authenticate header is required to be present. In the
        // absence of anything better, use the Cookie auth scheme from:
        // https://tools.ietf.org/html/draft-broyer-http-cookie-auth-00
        response.setHeader("WWW-Authenticate", String.format(
            "Cookie form-action=\"%s\", cookie-name=\"%s\"",
            escapeAuthenticateHeaderToken(url),
            escapeAuthenticateHeaderToken(this.cookieName)));

        // We still need to have browsers automatically go to the login page.
        // We can use the non-standard Refresh header for this purpose. It's
        // supported by every browser going, but crucially is not followed by
        // AJAX requests, so an AJAX request can see that it failed rather than
        // just getting a login form.
        response.setHeader("Refresh", "0; " + url);

        // Just in case a browser doesn't implement support for the Refresh
        // header, we'll send an HTML response with content to facilitate a
        // redirect.
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.getOutputStream().print(this.renderHtmlResponse(url));
    }
}
