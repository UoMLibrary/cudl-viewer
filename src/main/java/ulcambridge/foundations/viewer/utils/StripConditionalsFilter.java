package ulcambridge.foundations.viewer.utils;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Remove conditional headers (If-Modified-Since, etc.) from the request.
 * @see <a href="https://cam-ul.atlassian.net/browse/CUDL-197">CUDL-197</a>
 */
public class StripConditionalsFilter extends OncePerRequestFilter {

    private static boolean allowed(String name) {
        return !name.toLowerCase().startsWith("if-");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException
    {
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override
            public Enumeration<String> getHeaderNames() {
                return Collections.enumeration(
                    Collections.list(super.getHeaderNames()).stream()
                        .filter(StripConditionalsFilter::allowed)
                        .collect(Collectors.toList()));
            }

            @Override
            public Enumeration<String> getHeaders(String name) {
                return allowed(name) ? super.getHeaders(name) : Collections.emptyEnumeration();
            }

            @Override
            public String getHeader(String name) {
                return allowed(name) ? super.getHeader(name) : null;
            }

            @Override
            public long getDateHeader(String name) {
                return allowed(name) ? super.getDateHeader(name) : -1;
            }
        }, response);
    }
}
