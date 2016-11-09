package ulcambridge.foundations.viewer.authentication.distributed;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class DefaultJwtCreatorTest {

    interface VerifierCreator {
        JWTVerifier createVerifier(String issuer, String audience);
    }

    private static final class JWTSignerVerifier {
        public final JWTSigner signer;
        public final VerifierCreator verifier;
        public final List<Algorithm> algorithms;

        public JWTSignerVerifier(JWTSigner signer, VerifierCreator verifier,
                                 Collection<Algorithm> algorithms) {
            this.signer = signer;
            this.verifier = verifier;
            this.algorithms = ImmutableList.copyOf(algorithms);
        }
    }

    @Parameters
    public static Iterable<Object[]> parameters()
        throws UnsupportedEncodingException {

        PrivateKey privkey = getPrivateKey();
        PublicKey pubkey = getPublicKey();
        byte[] secret = "jfdsaaaghkajfklsjdafsdiojasdf".getBytes("UTF-8");

        JWTSignerVerifier[] signerVerifiers = new JWTSignerVerifier[]{
            new JWTSignerVerifier(
                new JWTSigner(secret),
                (issuer, aud) -> new JWTVerifier(secret, aud, issuer),
                Arrays.asList(Algorithm.HS256, Algorithm.HS384, Algorithm.HS512)),

            new JWTSignerVerifier(
                new JWTSigner(privkey),
                (issuer, aud) -> new JWTVerifier(pubkey, aud, issuer),
                Arrays.asList(Algorithm.RS256, Algorithm.RS384, Algorithm.RS512))
        };

        List<Object[]> params = new ArrayList<>();

        for(JWTSignerVerifier jsv : signerVerifiers) {
            for(Algorithm a : jsv.algorithms) {
                params.add(new Object[]{
                    jsv.signer, a, jsv.verifier, Duration.ofSeconds(30)
                });
            }
        }

        return params;
    }

    @Parameter
    public JWTSigner signer;

    @Parameter(1)
    public Algorithm algorithm;

    @Parameter(2)
    public VerifierCreator verifier;

    @Parameter(3)
    public Duration lifetime;

    private DefaultJwtCreator getCreator(
        Predicate<URI> acceptableAudienceUrl, Clock clock) {

        return new DefaultJwtCreator(acceptableAudienceUrl, signer,
                                     algorithm, clock, lifetime);
    }

    @Test(expected = UnacceptableAudienceUrlTokenException.class)
    public void testAudienceIsRejected() throws TokenException {
        getCreator(url -> false, Clock.systemUTC()).createJwt(
            URI.create("https://example.com/"),
            URI.create("https://foo.example.com/"),
            "bob");
    }

    @Test
    public void testRoundTrip()
        throws TokenException, SignatureException, NoSuchAlgorithmException,
        JWTVerifyException, InvalidKeyException, IOException {

        Clock clock = Clock.fixed(Instant.now(), ZoneId.of("UTC"));

        URI issuer = URI.create("https://example.com/");
        URI audience = URI.create("https://foo.example.com/");

        String jwt = getCreator(url -> true, clock)
            .createJwt(issuer, audience, "bob");

        Map<String, Object> claims = verifier
            .createVerifier(issuer.toString(), audience.toString())
            .verify(jwt);

        assertThat(((Integer)claims.get("iat")).longValue(),
                   equalTo(clock.instant().getEpochSecond()));

        assertThat(
            ((Integer)claims.get("nbf")).longValue(),
            equalTo(clock.instant()
                .minus(DefaultJwtCreator.HISTORIC_VALIDITY_PERIOD)
                .getEpochSecond()));

        assertThat(((Integer)claims.get("exp")).longValue(),
                   equalTo(clock.instant().plus(lifetime).getEpochSecond()));
        assertThat(claims.get("iss"), is(issuer.toString()));
        assertThat(claims.get("aud"), is(audience.toString()));
        assertThat(claims.get("sub"), is("bob"));
    }

    private static final byte[] decodeb64(String s) {
        return Base64.getDecoder().decode(s);
    }

    /**
     * Generated with:
     *
     * <pre>{@code
     * $ ssh-keygen -N '' -t rsa -b 2048 -f jwt-key
     * $ openssl pkcs8 -nocrypt -topk8 -in jwt-key -outform DER | base64 -w 68
     * }</pre>
     */
    public static final byte[] TEST_RSA_KEY_PRIV = decodeb64(
        "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCrHDghezDw8ePf4qr9" +
        "JyYScWlejl7a6JsCEmP3j+mGh4x2Xg2UEz3y7gF4UTwrQ7yw+5UN6Q/9A997UDQQYzue" +
        "w0w0nWB/sHgRDdU5LIDmiOi/4cPPWOVFDINSF3fbmMx6OOXbGAWCcpQTGq0hU586ThMk" +
        "pnPTTPhoWZopulw4k6ypOAbaLd3/vksGMBEcwskyfzsngXArI+kga9VuRptpEEQrH19C" +
        "zPZJbknahzrX39tpq2NnZvPsqC+FSh+elRRmqYTpzV+putpgjMpqRSP7J8SeM0cN6VXc" +
        "qYRHhXOgHiFMEvIbczcSZzU2MjuiCq5CD1Zdgbh7rAxcoqDwVBu/AgMBAAECggEAKb+K" +
        "2nBqMn9yL8/oFDgXC+zr3owyDIswNsMx7NcKDS7JUKAGBBjlxn3XkfmQCqZORYg8h9ZT" +
        "dlIZlsaszUrI4yWXVEcJol32DYMogPigwp6o2xhEZDS2S7CP4dmj/so7KZ70Rg6IWZmH" +
        "E1ow3669bMZb2VdbbzSabytdd8zmb08CVHxaY1gxLu/KN4UZzyxD1I7F7teeHFa7QLiU" +
        "syN8R+3ZkbfUb+lWId0FluI5z7RfVKnMLrV660cLiojTfLkxvWsYfvdXSzici+94waJ3" +
        "Rs2D5d5eIvZw2g+FJgE6uLyLVkqKGpLJyaEpmYIOy7VgHwySr5Sl0/aO7RfxvezX0QKB" +
        "gQDbfnWMPbc8qxsQsBvmnr2q3HceenqGJRFC8fHYUHOXWpv4qQW5fLX15cTUTI3GiKPy" +
        "Jg0G7owI/QQM2pYQs7QnK3kY9UHmrZ0sDvYfVNCsfQKbPiY5LzyFk3bVLKece0GE3B+e" +
        "l1+aU8zOrH4piJcQHeSD6Q1nXim1ncnpLKTUOwKBgQDHkbFuKQWfhPjlHCpd2RVuwdVa" +
        "OXlWouS0+8qf2MEP2WUgIMTbJ8EnuQJCa45N4vivQmI/AW0H7yEg4WM9SijFrTsmV77U" +
        "GtMcK60zBefaMK0TSo+yHHblF0XYOeuAVpnAiuGc41Jl0tMWmu+G6YPSlVCcJYDxNJ8U" +
        "Hg9lBtpyTQKBgQCAeigiG6na+CjSftMGDdrlXUDYdUasqJvO/MHcJVNTv7TWO1FffnEf" +
        "6wtoXRsLn8WfIsizSwRq6nbpczUtt5J27wpmIoEdnngGZweH1WSD4nSZHCrRhCW/5k5D" +
        "f2zounjiZNqZQO+z7ONQAkWi2BHcXDL7R3oSDFsLtL2QIBKnKwKBgDla6uZhDcepvKqD" +
        "7L0qDZnWRU335KJ8kERfdP15mwrGDOUt5cWiaEXVSwvxw2UpDRW5e2jmLQKxvBCqFg5g" +
        "SNV/EtfTMfndd7zJ5K4cTWUMxkEcFa43tgfjJ2ScSM2KlgebInonbt/qtlXx01Mvu34D" +
        "AbbOpH8uA2YRuZTsYk2lAn9PAa1Ya5WcFoFf6ncf0wKGuVvTD+yum8W9oZoiOrpKQ3kx" +
        "5NJ20eqY3BGEGkqLStqqP/Q5BG9/yh5/uixpx+buw4GAiL6r2Ctt5DzDKC3wrH9OiS5z" +
        "XrERchJyO1djnynxoSuvZQCht9nyuatg29Rx9XQCMdaE5eo01MRCra03");

    /**
     * Generated from the above private key with:
     *
     * <pre>{@code
     * $ openssl rsa -in jwt-key -outform PEM -pubout | openssl rsa -pubin -inform PEM -text -noout
     * }</pre>
     *
     * This prints the exponent and modulus of the public key.
     */
    private static final BigInteger TEST_RSA_KEY_PUB_MOD = new BigInteger(
        "21600665585372744541023023345195782574684608644650379693724116134802" +
        "67658362503402395538618797238666380241258349072571774699168258354373" +
        "58247016416435310471552777928265084420705310072245638771627631108004" +
        "83065783475780733116917450483668639723673371819553823531768739681118" +
        "38950724644710893254195572228562931292378165876881332547527074539419" +
        "32392264126598808517984571585838152782924287102596898466697849113868" +
        "65930228738774802115208253826017215926962452172588531231037492007424" +
        "66337255043309656536054719082756919864081261528580707443167986042600" +
        "54051127360513229701130541717837793204003163727970926703190439081009" +
        "55071");

    private static final BigInteger TEST_RSA_KEY_PUB_EXP =
        new BigInteger("65537");

    private static final KeyFactory rsaKeyFactory() {
        try {
            return KeyFactory.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey getPrivateKey() {
        try {
            return rsaKeyFactory()
                .generatePrivate(new PKCS8EncodedKeySpec(TEST_RSA_KEY_PRIV));
        }
        catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey getPublicKey() {
        try {
            return rsaKeyFactory()
                .generatePublic(new RSAPublicKeySpec(TEST_RSA_KEY_PUB_MOD,
                                                     TEST_RSA_KEY_PUB_EXP));
        }
        catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }


}
