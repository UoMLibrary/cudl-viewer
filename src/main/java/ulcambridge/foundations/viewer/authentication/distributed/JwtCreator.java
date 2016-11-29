package ulcambridge.foundations.viewer.authentication.distributed;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

public interface JwtCreator {
    String createJwt(URI issuerUrl, URI audience, String username,
                     Optional<Duration> lifetime) throws TokenException;
}
