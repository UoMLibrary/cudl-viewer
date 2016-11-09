package ulcambridge.foundations.viewer.authentication.distributed;

import java.net.URI;
import java.util.function.Predicate;
import java.util.regex.Pattern;


public class AcceptableAudiences {

    public static Predicate<URI> urlSubdomainMatcher(String referenceDomain) {
        Predicate<String> subdomainMatcher = subdomainMatcher(referenceDomain);

        return url ->
            url.getHost() != null && subdomainMatcher.test(url.getHost());
    }

    /**
     * Check if {@code testDomain} is a subdomain of {@code referenceDomain}.
     */
    public static Predicate<String> subdomainMatcher(String referenceDomain) {

        return Pattern.compile(String.format(
            "(?:^|\\.)%s$", Pattern.quote(referenceDomain))).asPredicate();
    }
}
