package ulcambridge.foundations.viewer.authentication.distributed;

import java.net.URI;

public interface JwtCreator {
    String createJwt(URI issuerUrl, URI audience, String username)
        throws TokenException;
}
