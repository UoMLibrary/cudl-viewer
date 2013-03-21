package ulcambridge.foundations.viewer.forms;

import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SearchForm {

	protected final Log logger = LogFactory.getLog(getClass());

	// Keyword information	
	private String keyword = "";
	private String fullText = "";
	private String excludeText = "";
	private String textJoin = "and";
	private String fileID = "";

	// Metadata
	private String title = "";
	private String author = "";
	private String subject = "";
	private int yearStart = 0;
	private int yearEnd = 0;
	
	// Search Facets
	private Map<String, String> facets = new Hashtable<String,String>();
	private String facetDate;
	private String facetSubject;
	private String facetCollection;	

	public String getKeyword() {
		return keyword;
	}

	public void setKeyword(String keyword) {
		this.keyword = keyword;
	}

	public String getExcludeText() {
		return excludeText;
	}

	public void setExcludeText(String excludeText) {
		this.excludeText = excludeText;
	}
	
	public String getFullText() {
		return fullText;
	}

	public void setFullText(String fullText) {
		this.fullText = fullText;
	}
	

	public String getTextJoin() {
		return textJoin;
	}

	public void setTextJoin(String textJoin) {
		this.textJoin = textJoin;
	}
	
	public String getFileID() {
		return fileID;
	}

	public void setFileID(String fileID) {
		this.fileID = fileID;
	}
	
	/** Metadata **/

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public int getYearStart() {
		return yearStart;
	}

	public void setYearStart(int yearStart) {
		this.yearStart = yearStart;
	}

	public int getYearEnd() {
		return yearEnd;
	}

	public void setYearEnd(int yearEnd) {
		this.yearEnd = yearEnd;
	}

	
	/** Facets **/
	
	public String getFacetDate() {
		return facetDate;
	}

	public void setFacetDate(String facetDate) {
		this.facetDate = facetDate;
		facets.put("date", facetDate);
	}

	public String getFacetSubject() {
		return facetSubject;
	}

	public void setFacetSubject(String facetSubject) {
		this.facetSubject = facetSubject;
		facets.put("subject", facetSubject);
	}

	public String getFacetCollection() {
		return facetCollection;
	}

	public void setFacetCollection(String facetCollection) {
		this.facetCollection = facetCollection;
		facets.put("collection", facetCollection);
	}
	
	public Map<String, String> getFacets() {
		
		return facets;
	}

	/**
	 * Sets the values in this form to the values in the form passed in. 
	 * 
	 * @return
	 */
	public void setValuesFrom(SearchForm input) {
		
		this.keyword = input.keyword;
		this.textJoin = input.textJoin;
		this.fullText = input.fullText;
		this.excludeText = input.excludeText;
		this.fileID = input.fileID;
		
		this.title = input.title;
		this.author = input.author;
		this.subject = input.subject;
		this.yearStart = input.yearStart;
		this.yearEnd = input.yearEnd;
		
		this.facetCollection = input.facetCollection;
		this.facetDate = input.facetDate;
		this.facetSubject = input.facetSubject;		
		Hashtable<String, String> facets = new Hashtable<String, String>();
		facets.putAll(input.facets);
		this.facets = facets;		
	}

}