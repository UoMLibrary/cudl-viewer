package ulcambridge.foundations.viewer.search;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.Map;

/**
 * Holds information for a Search Query including facet refinement.
 * 
 * @author jennie
 * 
 */
public class SearchQuery {

	private String keyword;
	private String fileID;
	private String keywordDisplay;
	private Map<String, String> facets;

	/**
	 * Creates a new SearchQuery from the given Node.
	 */
	public SearchQuery(String keyword, String fileID, Map<String, String> map) {

		this.keyword = keyword; 
		this.fileID = fileID;
		this.keywordDisplay = keyword;
		this.facets = map;
	}

	public String getKeyword() {
		return keyword;
	}
	
	public String getFileID() {
		return fileID;
	}	
	
	public String getKeywordDisplay() {
		return keywordDisplay;
	}	

	public Map<String, String> getFacets() {
		return facets;
	}

	public String getURLParameters() {
		try {
			String params = "keyword=" + URLEncoder.encode(keyword, "UTF-8");
			params += "&amp;fileID=" + URLEncoder.encode(fileID, "UTF-8");
			Iterator<String> facetIterator = facets.keySet().iterator();
			while (facetIterator.hasNext()) {
				String facet = facetIterator.next().toString();
				params += "&amp;facet-" + URLEncoder.encode(facet, "UTF-8") + "="
						+ URLEncoder.encode(facets.get(facet), "UTF-8");
			}
			return params;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	public String getURLParametersWithoutFacet(String facetName) {
		try {
			String params = "keyword=" + URLEncoder.encode(keyword, "UTF-8");
			params += "&amp;fileID=" + URLEncoder.encode(fileID, "UTF-8");			
			Iterator<String> facetIterator = facets.keySet().iterator();
			while (facetIterator.hasNext()) {
				String facet = facetIterator.next().toString();
				if (!facet.equals(facetName)) {
					params += "&amp;facet-" + URLEncoder.encode(facet, "UTF-8")
							+ "="
							+ URLEncoder.encode(facets.get(facet), "UTF-8");
				}
			}
			return params;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	public String getURLParametersWithExtraFacet(String facetName,
			String facetValue) {
		try {
			return getURLParameters() + "&amp;facet-"
					+ URLEncoder.encode(facetName, "UTF-8") + "="
					+ URLEncoder.encode(facetValue, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

}
