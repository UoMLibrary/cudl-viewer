package ulcambridge.foundations.viewer.search;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import ulcambridge.foundations.viewer.forms.SearchForm;
import ulcambridge.foundations.viewer.model.Properties;

public class XTFSearch implements Search {

	/**
	 * Returns the 'maxDocs' number of results starting at the first one. 
	 * Maxdocs is specified inside XTF configuration. 
	 */	
	@Override
	public SearchResultSet makeSearch(SearchForm searchForm) {
		return makeSearch(searchForm, 1, 1);
	}
	
	/**
	 * Request XTF keyword search (raw=1 to return XML)
	 * Returns the 'maxDocs' number of results starting at the specified start. 
	 * Maxdocs is specified inside XTF configuration. 
	 */		
	@Override
	public SearchResultSet makeSearch(SearchForm searchForm, int start, int end) {

		// Construct the URL we are going to use to query XTF
		String searchXTFURL = buildQueryURL(searchForm, start, end);

		// if the query URL is null return empty result set.
		if (searchXTFURL == null) {
			return new SearchResultSet(0, "", 0f,
					new ArrayList<SearchResult>(), new ArrayList<FacetGroup>(),
					"A problem occurred making the search (xtf).");
		}

		// parse search results into a SearchResultSet
		return parseSearchResults(getDocument(searchXTFURL));

	}

	protected Document getDocument(String url) {

		// Read document from URL and put results in Document.
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		try {

			DocumentBuilder db = dbf.newDocumentBuilder();

			return db.parse(url);

		} catch (Exception e) {
			e.printStackTrace();

		}

		return null;
	}

	protected String buildQueryURL(SearchForm searchForm, int start, int end) {

		String xtfURL = Properties.getString("xtfURL");
		String searchXTFURL = xtfURL + "search?raw=1&smode=advanced&startDoc="+start;

		try {

			// Keywords
			if (searchForm.getKeyword() != null) {

				searchXTFURL += "&keyword="
						+ URLEncoder.encode(searchForm.getKeyword(), "UTF-8");
			}
			if (searchForm.getFullText() != null) {

				searchXTFURL += "&text="
						+ URLEncoder.encode(searchForm.getFullText(), "UTF-8");
			}
			if (searchForm.getExcludeText() != null) {

				searchXTFURL += "&text-exclude="
						+ URLEncoder.encode(searchForm.getExcludeText(),
								"UTF-8");
			}

			// Join
			if (searchForm.getTextJoin() != null) {

				if (searchForm.getTextJoin().equals("or")) {
					searchXTFURL += "&text-join=or";
				} else {
					searchXTFURL += "&text-join=";
				}

			}

			// File ID
			if (searchForm.getFileID() != null) {

				searchXTFURL += "&fileID="
						+ URLEncoder.encode(searchForm.getFileID(), "UTF-8");
			}

			// Metadata
			if (searchForm.getTitle() != null) {

				searchXTFURL += "&title="
						+ URLEncoder.encode(searchForm.getTitle(), "UTF-8");
			}
			if (searchForm.getAuthor() != null) {

				searchXTFURL += "&nameFullForm="
						+ URLEncoder.encode(searchForm.getAuthor(), "UTF-8");
			}
			if (searchForm.getSubject() != null) {

				searchXTFURL += "&subjectFullForm="
						+ URLEncoder.encode(searchForm.getSubject(), "UTF-8");
			}
			if (searchForm.getYearStart() != null) {

				searchXTFURL += "&year=" + searchForm.getYearStart();
			}
			if (searchForm.getYearEnd() != null) {

				searchXTFURL += "&year-max=" + searchForm.getYearEnd();
			}

			// Facets
			int facetCount = 0; // xtf needs to know order of facets.
			if (searchForm.getFacetCollection() != null) {

				facetCount++;
				searchXTFURL += "&f"
						+ facetCount
						+ "-collection="
						+ URLEncoder.encode(searchForm.getFacetCollection(),
								"UTF-8");
			}

			if (searchForm.getFacetSubject() != null) {

				facetCount++;
				searchXTFURL += "&f"
						+ facetCount
						+ "-subject="
						+ URLEncoder.encode(searchForm.getFacetSubject(),
								"UTF-8");
			}

			if (searchForm.getFacetDate() != null) {

				facetCount++;
				searchXTFURL += "&f" + facetCount + "-date="
						+ URLEncoder.encode(searchForm.getFacetDate(), "UTF-8");
			}

		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
		}

		// System.out.println(searchXTFURL);
		return searchXTFURL;
	}

	/**
	 * Parse the XML dom document and put the results into a list of
	 * SearchResult objects.
	 * 
	 * @param dom
	 * @return List of the search results
	 */
	protected SearchResultSet parseSearchResults(Document dom) {

		// Check input - XTF may be down.
		if (dom == null) {
			return new SearchResultSet(0, "", 0f,
					new ArrayList<SearchResult>(), new ArrayList<FacetGroup>(),
					"A problem occurred making the search (xtf).");
		}

		// Get the root element
		Element docEle = dom.getDocumentElement();
		ArrayList<SearchResult> results = new ArrayList<SearchResult>();

		// Catch any errors
		if (!docEle.getNodeName().equals("crossQueryResult")) {
			return new SearchResultSet(
					0,
					"",
					0f,
					new ArrayList<SearchResult>(),
					new ArrayList<FacetGroup>(),
					"Too many results, try a smaller range, eliminating wildcards, or making them more specific. ");
		}

		// Add in all the (docHit) results into a Hashtable by Item Number
		NodeList docHits = docEle.getElementsByTagName("docHit");

		if (docHits != null) {
			for (int i = 0; i < docHits.getLength(); i++) {

				Element node = (Element) docHits.item(i);
				Element meta = (Element) node.getElementsByTagName("meta")
						.item(0);

				Element itemIdElement = (Element) meta.getElementsByTagName(
						"fileID").item(0);

				// Sometimes results may appear without any metadata, ignore
				// these.
				if (itemIdElement != null) {
					String itemId = getValueInText(itemIdElement);

					itemId = itemId.replaceAll("\\s+", ""); // remove whitespace

					SearchResult result = createSearchResult(node);
					results.add(result);

				}
			}

			// ensure results are in the right order by score.
			if (results.size() > 0) {
				Collections.sort(results);
			}

		}

		// Get general search result data
		int totalDocs = Integer.parseInt(docEle.getAttribute("totalDocs"));
		float queryTime = Float.parseFloat(docEle.getAttribute("queryTime"));
		Element spelling = (Element) docEle.getElementsByTagName("spelling")
				.item(0);
		String suggestedTerm = "";
		if (spelling != null) {
			Element suggestion = (Element) spelling.getElementsByTagName(
					"suggestion").item(0);
			suggestedTerm = suggestion.getAttribute("suggestedTerm");
		}

		// facets
		ArrayList<FacetGroup> facetGroups = new ArrayList<FacetGroup>();
		for (int i=0; i<docEle.getChildNodes().getLength(); i++) {
			Node childNode = docEle.getChildNodes().item(i);
			
			if (childNode.getNodeName().equals("facet")) {
				
				Element facetElement = (Element) childNode;
				ArrayList<Facet> facets = new ArrayList<Facet>(); 
				String field = facetElement.getAttributes().getNamedItem("field").getTextContent();
				field = field.replace("facet-", ""); // remove facet- from that start. 
				
				int facetGroupOccurances = Integer.parseInt(facetElement.getAttributes().getNamedItem("totalDocs").getTextContent());
				
				NodeList groups = facetElement.getElementsByTagName("group");
				for (int j=0; j<groups.getLength(); j++) {
					Node facetNode = groups.item(j);					
					String band = facetNode.getAttributes().getNamedItem("value").getTextContent();					
					int occurances = Integer.parseInt(facetNode.getAttributes().getNamedItem("totalDocs").getTextContent());
					int rank = Integer.parseInt(facetNode.getAttributes().getNamedItem("rank").getTextContent());
					Facet facet = new Facet(field, band, occurances, rank);
					facets.add(facet);
				}
				
				FacetGroup facetGroup = new FacetGroup(field, facets, facetGroupOccurances);
				facetGroups.add(facetGroup);
			}
		}
		
		return new SearchResultSet(totalDocs, suggestedTerm, queryTime,
				results, facetGroups, "");
	}

	/**
	 * Creates a new SearchResult from the given Node.
	 */
	public SearchResult createSearchResult(Element node) {

		String title = "";
		String id = "";
		int score = -1;
		int startPage = 0;
		String startPageLabel = "";
		List<String> snippets = new ArrayList<String>();

		// look at all the child tags
		if (node.getNodeName().equals("docHit")) {

			// META Search Info.
			Element meta = (Element) node.getElementsByTagName("meta").item(0);

			title = getValueInHTML(meta.getElementsByTagName("title").item(0));
			id = getValueInText(meta.getElementsByTagName("fileID").item(0));

			id = id.replaceAll("\\s+", ""); // remove whitespace

			score = Integer.parseInt(node.getAttribute("score"));

			startPage = new Integer(meta.getElementsByTagName("startPage")
					.item(0).getFirstChild().getTextContent()).intValue();

			startPageLabel = node.getElementsByTagName("startPageLabel")
					.item(0).getTextContent();

			NodeList snippetNodes = node.getElementsByTagName("snippet");

			for (int i = 0; i < snippetNodes.getLength(); i++) {
				Node snippetNode = snippetNodes.item(i);
				String snippet = getValueInHTML(snippetNode);
				snippets.add(snippet);
			}

		}

		return new SearchResult(title, id, startPage, startPageLabel,
				snippets, score);

	}

	/**
	 * Return a flat string with just the text value of a specified node (and
	 * any sub-nodes).
	 * 
	 * @param node
	 * @return
	 */
	public String getValueInText(Node node) {

		if (node.getNodeType() == Node.TEXT_NODE) {
			if (node.getParentNode().getNodeName().equals("term")) {
				return node.getNodeValue().replaceAll("<.*>", "");
			}
			// remove complete and partial tags as much as possible
			String noCompleteTags = node.getNodeValue().replaceAll("<.*>", "");
			return noCompleteTags.replaceAll("<\\w*|\\w*>", "");
		}

		NodeList children = node.getChildNodes();
		StringBuffer textValue = new StringBuffer();
		if (node.getNodeValue() == null && children != null) {

			for (int i = 0; i < children.getLength(); i++) {
				Node child = children.item(i);
				textValue.append(getValueInText(child));
			}

			return textValue.toString();
		}

		return "";

	}

	/**
	 * Strips out the tags from node and flattens content. Where a value appears
	 * in <hit><term> tags this is translated into <b> html.
	 * 
	 * Recursive.
	 * 
	 * @param node
	 * @return
	 */
	public String getValueInHTML(Node node) {

		if (node == null)
			return "";

		if (node.getNodeType() == Node.TEXT_NODE) {
			// if this is a snippet, bold the matching word(s).
			if (node.getParentNode().getNodeName().equals("term")) {
				return "<b>" + node.getNodeValue().replaceAll("<.*>", "")
						+ "</b>";
			}
			// remove complete and partial tags as much as possible
			String noCompleteTags = node.getNodeValue().replaceAll("<.*>", "");
			return noCompleteTags.replaceAll("<\\w*|\\w*>", "");
		}

		NodeList children = node.getChildNodes();
		StringBuffer textValue = new StringBuffer();
		if (node.getNodeValue() == null && children != null) {

			for (int i = 0; i < children.getLength(); i++) {
				Node child = children.item(i);
				textValue.append(getValueInHTML(child));
			}

			return textValue.toString();
		}

		return "";

	}

}
