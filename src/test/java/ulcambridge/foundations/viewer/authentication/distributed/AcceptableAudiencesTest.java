package ulcambridge.foundations.viewer.authentication.distributed;

import org.junit.Test;

import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import static ulcambridge.foundations.viewer.authentication.distributed.AcceptableAudiences.subdomainMatcher;
import static ulcambridge.foundations.viewer.authentication.distributed.AcceptableAudiences.urlSubdomainMatcher;

public class AcceptableAudiencesTest {

    private static void testUrlMatch(String domain, String url,
                                     boolean shouldMatch) {
        assertThat(urlSubdomainMatcher(domain)
                .test(URI.create(url)),
            is(shouldMatch));
    }

    @Test
    public void testUrlSubdomainMatcher1() {
        testUrlMatch("cudl.lib.cam.ac.uk",
                     "http://services.cudl.lib.cam.ac.uk/", true);
    }

    @Test
    public void testUrlSubdomainMatcher2() {
        testUrlMatch("cudl.lib.cam.ac.uk",
                     "http://cudl.lib.cam.ac.uk/", true);
    }

    @Test
    public void testUrlSubdomainMatcherNegative1() {
        testUrlMatch("cudl.lib.cam.ac.uk",
                     "http://services.cudl-dev.lib.cam.ac.uk/", false);
    }

    @Test
    public void testUrlSubdomainMatcherNegative2() {
        testUrlMatch("cudl.lib.cam.ac.uk",
                     "http://services.cudl.lib.cam.ac.uk.blah/", false);
    }

    private static void testSubdomainMatch(String refDomain, String testDomain,
                                           boolean shouldMatch) {
        assertThat(subdomainMatcher(refDomain).test(testDomain),
            is(shouldMatch));
    }

    @Test
    public void testSubdomainMatch1() {
        testSubdomainMatch("a", "a", true);
    }

    @Test
    public void testSubdomainMatch2() {
        testSubdomainMatch("bar", "foo.bar", true);
    }

    @Test
    public void testSubdomainMatch3() {
        testSubdomainMatch("lib.cam.ac.uk", "cudl.lib.cam.ac.uk", true);
    }

    @Test
    public void testSubdomainMatch4() {
        testSubdomainMatch("lib.cam.ac.uk", "cudl.lib.cam.ac.uk.foo", false);
    }
}
