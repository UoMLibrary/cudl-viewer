<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ page
	import="java.util.*,java.net.URLEncoder,ulcambridge.foundations.viewer.search.*,ulcambridge.foundations.viewer.model.Item,ulcambridge.foundations.viewer.ItemFactory,ulcambridge.foundations.viewer.forms.SearchForm,org.owasp.encoder.Encode"%>
<jsp:include page="header/header-full.jsp" />
<jsp:include page="header/nav.jsp">
	<jsp:param name="activeMenuIndex" value="1" />
	<jsp:param name="displaySearch" value="true" />
	<jsp:param name="title" value="Advanced Search: Results" />
</jsp:include>

<%
	SearchResultSet resultSet = ((SearchResultSet) request
	.getAttribute("results"));
	SearchForm form = ((SearchForm) request.getAttribute("form"));
%>

<!--  script for ajax pagination -->
<script type="text/javascript">

var viewPage = function(pageNum) {
	 if (window.history.replaceState) {
		 window.history.replaceState(pageNum, "Cambridge Digital Library",
				 "#"+pageNum);
	 } else if (window.location){
		 window.location.hash = pageNum;
	 }
	 return false;
};

function pageinit() {
	
  var pageLimit = 20;
  var numResults = <%=resultSet.getNumberOfResults()%>;
  
  // Setup spinner. 
  var opts = {
		  length: 7, // The length of each line
		  width: 4, // The line thickness
		  radius: 10, // The radius of the inner circle
		};
		var target = document.getElementById('content');
		var spinner = new Spinner(opts);
		
  // Setup pagination
  var Paging = $(".pagination").paging(
	numResults,
	{

		format : "< (q-) ncnnnnnn (-p) >",  //[< (q-) ncnnnnnn (-p) >]
		perpage : pageLimit,
		lapping : 0,
		page : 1,
		onSelect : function(page) {

			spinner.spin(target);				   	
			
	        $.ajax({
                "url": '/search/JSON?start=' + this.slice[0] + '&end=' + this.slice[1] +'&<%=request.getQueryString()%>',
											"success" : function(data) {

												spinner.stop();

												// content replace					                   
												var container = document
														.getElementById("collections_carousel");

												// Remove all children
												container.innerHTML = '';

												// add in the results
												for (var i = 0; i < data.length; i++) {
													var result = data[i];
													var item = result.item;
													var imageDimensions = "";
													if (item.thumbnailOrientation == "portrait") {
														imageDimensions = " style='height:100%' ";
													} else if (item.thumbnailOrientation == "landscape") {
														imageDimensions = " style='width:100%' ";
													}
													var title = item.title;
													if (result.itemType == "essay") {
														title = "Essay: "
																+ title;
													}

													var itemDiv = document
															.createElement('div');
													itemDiv
															.setAttribute(
																	"class",
																	"collections_carousel_item");
													var itemText = "<div class='collections_carousel_image_box campl-column4'>"
															+ "<div class='collections_carousel_image'>"
															+ "<a href='/view/" +item.id+ "/"+result.startPage+"'><img src='" +result.pageThumbnailURL+ "' alt='" +item.id+ "' "+
				        imageDimensions+ " > </a></div></div> "
															+ "<div class='collections_carousel_text campl-column8'><h5>"
															+ title
															+ " <font style='color:#999'>("
															+ item.shelfLocator
															+ " Page: "
															+ result.startPageLabel
															+ ")</font></h5> "
															+ item.abstractShort
															+ " ... <br/><br/><ul>";

													for (var j = 0; j < result.snippets.length; j++) {

														var snippet = result.snippets[j];

														if (snippet != ""
																&& snippet != "undefined") {
															var snippetLabel = "";
															itemText += "<li><a href='/view/" +item.id+ "/"+result.startPage+"'>"
																	+ snippet
																	+ "</a> </li>";
														}

													}

													itemText += "</ul></div><div class='clear'></div>";
													itemDiv.innerHTML = itemText;
													container
															.appendChild(itemDiv);

												}

												/*
												$('.collections_carousel_text').truncate({  
												    max_length: 260,  
												     more: "view more",  
												     less: "hide"
												 }); 
												 */
											}
										});

								return false;
							},

							onFormat : function(type) {

								switch (type) {

								case 'block':

									if (!this.active)
										return '<span class="disabled">'
												+ this.value + '</span>';
									else if (this.value != this.page)
										return '<em><a href="" onclick="viewPage('
												+ this.value
												+ '); return false;">'
												+ this.value + '</a></em>';
									return '<span class="current">'
											+ this.value + '</span>';

								case 'right':
								case 'left':

									if (!this.active) {
										return '';
									}
									return '<a href="" onclick="viewPage('
											+ this.value + '); return false;">'
											+ this.value + '</a>';

								case 'next':

									if (this.active)
										return '<a href="" onclick="viewPage('
												+ this.value
												+ '); return false;" class="next"><img src="/img/interface/icon-fwd-btn-larger.png" class="pagination-fwd"/></a>';
									return '<span class="disabled"><img src="/img/interface/icon-fwd-btn-larger.png" class="pagination-fwd"/></span>';

								case 'prev':

									if (this.active)
										return '<a href="" onclick="viewPage('
												+ this.value
												+ '); return false;" class="prev"><img src="/img/interface/icon-back-btn-larger.png" class="pagination-back"/></a>';
									return '<span class="disabled"><img src="/img/interface/icon-back-btn-larger.png" class="pagination-back"/></span>';

								case 'first':

									if (this.active)
										return '<a href="" onclick="viewPage('
												+ this.value
												+ '); return false;" class="first">|<</a>';
									return '<span class="disabled">|<</span>';

								case 'last':

									if (this.active)
										return '<a href="" onclick="viewPage('
												+ this.value
												+ '); return false;" class="last">>|</a>';
									return '<span class="disabled">>|</span>';

								case "leap":

									if (this.active)
										return "...";
									return "";

								case 'fill':

									if (this.active)
										return "...";
									return "";
								}
							}
						});

		// Handle updating the Page selected from the hash part of the URL
		var hashChange = function() {

			if (window.location.hash)
				Paging.setPage(window.location.hash.substr(1));
			else
				Paging.setPage(1); // we dropped the initial page selection and need to run it manually
		};

		$(window).bind('hashchange', hashChange);
		hashChange();

		// Show the pagination toolbars if enough elements are present
		if ((numResults / pageLimit) > 1) {
			$(".toppagination")[0].style.display = "block";
			$(".toppagination")[1].style.display = "block";
		} else {
			$(".toppagination")[0].style.display = "none";
			$(".toppagination")[1].style.display = "none";
		}

	}
</script>
<div class="campl-row campl-content campl-recessed-content">
	<div class="campl-wrap clearfix">
		<div class="campl-main-content" id="content">
			<div>
				<div class="campl-column4 campl-secondary-content">

					<div class="searchform box">
						<div class="campl-content-container">
							<ul>
								<%
									if (!form.getKeyword().isEmpty()) {
										out.println("<li>Keyword: <b>" + Encode.forHtml(form.getKeyword())
												+ "</b></li>");
									}
								%>
								<%
									if (!form.getFullText().isEmpty()) {
										out.println("<li>Full Text: <b>" + Encode.forHtml(form.getFullText())
												+ "</b></li>");
									}
								%>
								<%
									if (!form.getExcludeText().isEmpty()) {
										out.println("<li>Exclude Text: <b>" + Encode.forHtml(form.getExcludeText())
												+ "</b></li>");
									}
								%>
								<%
									if (!form.getShelfLocator().isEmpty()) {
										out.println("<li>Classmark: <b>" + Encode.forHtml(form.getShelfLocator())
												+ "</b></li>");
									}
								%>
								<%
									if (!form.getFileID().isEmpty()) {
										out.println("<li>CUDL ID: <b>" + Encode.forHtml(form.getFileID()) + "</b></li>");
									}
								%>
								<%
									if (!form.getTitle().isEmpty()) {
										out.println("<li>Title: <b>" + Encode.forHtml(form.getTitle()) + "</b></li>");
									}
								%>
								<%
									if (!form.getAuthor().isEmpty()) {
										out.println("<li>Author: <b>" + Encode.forHtml(form.getAuthor()) + "</b></li>");
									}
								%>
								<%
									if (!form.getSubject().isEmpty()) {
										out.println("<li>Subject: <b>" + Encode.forHtml(form.getSubject())
												+ "</b></li>");
									}
								%>
								<%
									if (!form.getLocation().isEmpty()) {
										out.println("<li>Location: <b>" + Encode.forHtml(form.getLocation())
												+ "</b></li>");
									}
								%>
								<%
									if (form.getYearStart() != null && form.getYearEnd() != null) {
										out.println("<li>Year: <b>" + form.getYearStart()
												+ "</b> to <b>" + form.getYearEnd() + "</b></li>");
									}
								%>
							</ul>

							<form class="grid_5" action="/search">
								<a
									href="/search/advanced/query?<%=SearchUtil.getURLParameters(form)%>"><
									Change Query</a> <input type="hidden" name="fileID"
									value="<%=Encode.forHtmlAttribute(form.getFileID())%>">

							</form>

							<%
								Iterator<String> facetsUsed = form.getFacets().keySet().iterator();
								while (facetsUsed.hasNext()) {
									String facetName = facetsUsed.next();
									String facetValue = form.getFacets().get(facetName);
							%>
							<div class="search-facet-selected">
								<form action="/search/advanced/results">
									<a class="search-close"
										href="?<%=SearchUtil.getURLParametersWithoutFacet(form,
						facetName)%>&amp;">X</a>
									<%
										out.print("in "+Encode.forHtml(facetValue));
									%>
								</form>
							</div>
							<%
								}
								if (resultSet.getSpellingSuggestedTerm() != null
										&& !resultSet.getSpellingSuggestedTerm().equals("")) {
									out.println("Did you mean <a href=\"/search?keyword="
											+ resultSet.getSpellingSuggestedTerm() + "\">"
											+ resultSet.getSpellingSuggestedTerm() + "</a> ?");
								}
								out.println("<div class=\"campl-column12\"><br /><b>"
										+ resultSet.getNumberOfResults() + "</b>"
										+ " results were returned.<br/><br/></div>");
							%>
							<%
								if (resultSet.getNumberOfResults() > 0) {
							%>
						</div>
						<div class="campl-content-container">
							<h5>Refine by:</h5>

							<ol id="tree" class="campl-unstyled-list">
								<%
									List<FacetGroup> facetGroups = resultSet.getFacets();

										if (facetGroups != null) {

											for (int i = 0; i < facetGroups.size(); i++) {
												FacetGroup facetGroup = (FacetGroup) facetGroups.get(i);
												String fieldLabel = facetGroup.getFieldLabel();
												String field = facetGroup.getField();
												List<Facet> facets = facetGroup.getFacets();

												// Do not print out the facet for a field already faceting on
												if (!form.getFacets().containsKey(field)) {

													out.println("<li><strong>"
															+ fieldLabel
															+ "</strong><ul class='campl-unstyled-list'>");

													for (int j = 0; j < facets.size(); j++) {
														Facet facet = facets.get(j);

														out.print("<li><a href='?"
																+ SearchUtil
																		.getURLParametersWithExtraFacet(
																				form, Encode.forHtmlAttribute(field),
																				Encode.forHtmlAttribute(facet.getBand())) + "'>");
														out.print(Encode.forHtml(facet.getBand()) + "</a> ("
																+ facet.getOccurences() + ")</li>");

													}
													out.println("</ul></li>");
												}
											}
										}
								%>
							</ol>
							<%
								}
							%>
						</div>
					</div>
				</div>

				<div class="campl-column8" id="pagination_container">

					<div class="pagination toppagination"></div>
					<!-- start of list -->
					<div id="collections_carousel" class="collections_carousel">
					</div>
					<!-- end of list -->
					<div class="pagination toppagination"></div>


					<%
						List<SearchResult> results = resultSet.getResults();

						// No results were returned. So print out some help.
						if (resultSet.getNumberOfResults() == 0) {
							out.println("<p class=\"box\">We couldn't find any items your query.</p>");

							out.println("<div class=\"searchexample\">");
							out.println("<h5>Example Searches</h5><br/><p>");
							out.println("Searching for <span class=\"search\">newton</span> Searches the metadata for 'newton'<br/>");
							out.println("Searching for <span class=\"search\">isaac newton</span> Searches for 'isaac' AND 'newton'<br/>");
							out.println("Searching for <span class=\"search\">\"isaac newton\"</span> Searches for the phrase 'isaac newton'<br/>");
							out.println("The characters <b>?</b> and <b>*</b> can be used as wildcards in your search.<br />");
							out.println("Use <b>?</b> to represent one unknown character and <b>*</b> to represent any number of unknown characters.<br/>");
							out.println("</p></div>");
						}
					%>
				</div>


			</div>
		</div>
	</div>
</div>

<jsp:include page="header/footer-full.jsp" />




