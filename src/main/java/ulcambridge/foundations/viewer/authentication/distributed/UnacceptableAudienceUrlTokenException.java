package ulcambridge.foundations.viewer.authentication.distributed;

import org.springframework.util.Assert;

/**
 * Thrown when an attempt is made to create a JWT with an audience URL which is
 * not permitted. For example, the URL might be for an untrusted domain.
 */
public class UnacceptableAudienceUrlTokenException extends TokenException {

    private final String url;

    public UnacceptableAudienceUrlTokenException(String url) {
        this(url, null);
    }

    public UnacceptableAudienceUrlTokenException(String url, Throwable t) {
        super("Audience URL is not allowed: " + url, t);

        Assert.notNull(url);

        this.url = url;
    }
}
