package ulcambridge.foundations.viewer.authentication.distributed;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import org.springframework.util.Assert;

import java.net.URI;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

public class DefaultJwtCreator implements JwtCreator {

    public static final Duration DEFAULT_VALIDITY_PERIOD =
        Duration.ofSeconds(30);

    /**
     * Tokens will be valid for this period (Not Before claim) before the
     * current time. This is to specify a Not Before time without risking
     * initial invalidity in case a consumer's clock is slightly behind ours.
     */
    public static final Duration HISTORIC_VALIDITY_PERIOD =
        Duration.ofSeconds(5);

    private static final String CLAIM_ISSUED_AT = "iat";
    private static final String CLAIM_NOT_BEFORE = "nbf";
    private static final String CLAIM_EXPIRATION = "exp";
    private static final String CLAIM_ISSUER = "iss";
    private static final String CLAIM_AUDIENCE = "aud";
    private static final String CLAIM_SUBJECT = "sub";

    private final JWTSigner signer;
    private final Algorithm algorithm;
    private final Clock clock;
    private final Duration defaultLifetime;
    private final Duration maximumLifetime;
    private final Predicate<URI> isAcceptableAudienceURI;


    public DefaultJwtCreator(Predicate<URI> isAcceptableAudienceURI,
                             JWTSigner signer, Algorithm algorithm, Clock clock,
                             Duration defaultLifetime,
                             Duration maximumLifetime) {

        Assert.notNull(isAcceptableAudienceURI);
        Assert.notNull(signer);
        Assert.notNull(algorithm);
        Assert.notNull(clock);
        Assert.notNull(defaultLifetime);
        Assert.notNull(maximumLifetime);

        this.isAcceptableAudienceURI = isAcceptableAudienceURI;
        this.signer = signer;
        this.algorithm = algorithm;
        this.clock = clock;
        this.defaultLifetime = defaultLifetime;
        this.maximumLifetime = maximumLifetime;

        try {
            this.rejectInvalidDuration(this.defaultLifetime);
        }
        catch(TokenException e) {
            throw new IllegalArgumentException(
                "defaultLifetime is greater than maximumLifetime", e);
        }
    }

    public static DefaultJwtCreator create(
        Predicate<URI> isAcceptableAudienceURI,
        PrivateKey signingKey, Clock clock, Duration defaultLifetime) {

        return new DefaultJwtCreator(
            isAcceptableAudienceURI, new JWTSigner(signingKey),
            Algorithm.RS256, clock, defaultLifetime, Duration.ofDays(1));
    }

    public static DefaultJwtCreator create(
        Predicate<URI> isAcceptableAudienceURI,
        PrivateKey signingKey) {

        return create(isAcceptableAudienceURI, signingKey, Clock.systemUTC(),
                      DEFAULT_VALIDITY_PERIOD);
    }

    private JWTSigner.Options getOptions() {
        JWTSigner.Options o = new JWTSigner.Options();
        o.setAlgorithm(this.algorithm);
        return o;
    }

    public JWTSigner getJWTSigner() {
        return this.signer;
    }

    private Map<String, Object> getClaims(URI issuerUrl, URI audienceUrl,
                                          String username, Duration duration) {
        Map<String, Object> claims = new HashMap<>();

        Assert.isTrue(issuerUrl.isAbsolute());
        Assert.isTrue(audienceUrl.isAbsolute());
        Assert.hasText(username);

        Instant now = this.clock.instant();

        claims.put(CLAIM_ISSUED_AT, now.getEpochSecond());
        // It seems prudent to specify both a start and end validity time, so
        // that we don't mint a token valid for a long period of time in case of
        // our system clock being set in the far future by accident.
        claims.put(CLAIM_NOT_BEFORE,
            now.minus(HISTORIC_VALIDITY_PERIOD).getEpochSecond());
        claims.put(CLAIM_EXPIRATION, now.plus(duration).getEpochSecond());
        claims.put(CLAIM_ISSUER, issuerUrl.toString());
        claims.put(CLAIM_AUDIENCE, audienceUrl.toString());
        claims.put(CLAIM_SUBJECT, username);

        return claims;
    }

    private void rejectInvalidAudienceUrl(URI audienceUrl)
        throws TokenException {

        if(!this.isAcceptableAudienceURI.test(audienceUrl))
            throw new UnacceptableAudienceUrlTokenException(
                audienceUrl.toString());
    }

    private void rejectInvalidDuration(Duration duration)
        throws TokenException {

        if(duration.compareTo(Duration.ZERO) < 0) {
            throw new IllegalLifetimeTokenException(
                "The requested JWT lifetime was negative");
        }

        if(duration.compareTo(this.maximumLifetime) > 0) {
            throw new IllegalLifetimeTokenException(String.format(
                "The requested JWT lifetime of %s is greater than the maximum" +
                " permitted lifetime of %s.", duration, this.maximumLifetime));
        }
    }

    @Override
    public String createJwt(URI issuerUrl, URI audienceUrl, String username,
                            Optional<Duration> lifetime) throws TokenException {

        rejectInvalidAudienceUrl(audienceUrl);
        lifetime.ifPresent(this::rejectInvalidDuration);

        return getJWTSigner().sign(
            getClaims(issuerUrl, audienceUrl, username,
                      lifetime.orElse(this.defaultLifetime)),
            this.getOptions());
    }
}
