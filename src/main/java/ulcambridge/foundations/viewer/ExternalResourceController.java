package ulcambridge.foundations.viewer;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * Reads in the URL specified from cache if available, otherwise caches the
 * resource and then provides a link to the cached version.
 * 
 * @author jennie
 * 
 */
@Controller
public class ExternalResourceController {

	protected final Log logger = LogFactory.getLog(getClass());

	// on path /externalresource
	@RequestMapping(value = "/externalresource")
	public ModelAndView handleRequest(@RequestParam("url") String url,
			@RequestParam("doc") String docId, HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {

		// translate any relative url into an absolute value
		if (!url.startsWith("http")) {

			String baseURL = (request.getRequestURL().toString().replaceAll(
					"/externalresource", ""));
			url = baseURL + url;
		}

		// If the files doesn't exist in the cache, or has timed out, load file
		// into cache.
		if (!ExternalCache.existsInCache(url, docId)) {
			ExternalCache.loadIntoCache(url, docId);
		}

		// Note that if loading the page into cache failed it will still redirect to 
		// the cache url, this is because the file may have just timed out in 
		// which case we want to use the cached version. 
		String localURL = ExternalCache.getCachedItemLocalURL(url, docId);

		// String localURL = ExternalCache.getCachedItemLocalURL(url);
		// RequestDispatcher rd = request.getRequestDispatcher(localURL);
		// rd.forward(request, response);
		response.sendRedirect(localURL);
		return null;

	}
}