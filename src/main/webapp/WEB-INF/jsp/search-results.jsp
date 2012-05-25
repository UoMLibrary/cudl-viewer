<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ page
	import="java.util.*,java.net.URLEncoder,ulcambridge.foundations.viewer.search.*,ulcambridge.foundations.viewer.model.Item,ulcambridge.foundations.viewer.ItemFactory"%>
<jsp:include page="header/header-full.jsp" />
<jsp:include page="header/nav-search.jsp" />

<%
	SearchResultSet resultSet = ((SearchResultSet) request
			.getAttribute("results"));
	SearchQuery query = ((SearchQuery) request.getAttribute("query"));
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
  var Paging = $(".pagination").paging(
	numResults,
	{

		format : "[< (q-) ncnnnnnn (-p) >]",
		perpage : pageLimit,
		lapping : 0,
		page : 1,
		onSelect : function(page) {

	        $.ajax({
                "url": '/search/JSON?start=' + this.slice[0] + '&end=' + this.slice[1],
                "success": function(data) {
                	
                      // content replace					                   
				      var container = document.getElementById("collections_carousel");
				      
				      // Remove all children
				      container.innerHTML = '';

				      // add in the results
				      for (var i=0; i<data.length; i++) {
				    	  var item = data[i];
				    	  var imageDimensions = "";
						  if (item.thumbnailOrientation=="portrait") {
							imageDimensions = " style='height:100%' ";
						  } else if (item.thumbnailOrientation=="landscape") {
							imageDimensions = " style='width:100%' ";
						  }
							
				    	  var itemDiv = document.createElement('div');
				    	  itemDiv.setAttribute("class", "collections_carousel_item");
				    	  itemDiv.innerHTML= "<div class='collections_carousel_image_box'>"+
				        "<div class='collections_carousel_image'>"+
				        "<a href='/view/" +item.id+ "'><img src='" +item.thumbnailURL+ "' alt='" +item.id+ "' "+
				        imageDimensions+ " > </a></div></div> "+
				        "<div class='collections_carousel_text'><h5>" +item.title+ " (" +item.shelfLocator+ ")</h5> "+item.abstractShort+
				        " </div><div class='clear'></div>";
	           	        container.appendChild(itemDiv);
			 
				      
				      }	                        
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
					return '<em><a href="" onclick="viewPage('+ this.value + '); return false;">'
							+ this.value + '</a></em>';
				return '<span class="current">'
						+ this.value + '</span>';
						
			case 'right':
			case 'left':

				if (!this.active) {
					return '';
				}
				return '<a href="" onclick="viewPage('+ this.value + '); return false;">' + this.value + '</a>';
				
			case 'next':

				if (this.active)
					return '<a href="" onclick="viewPage('+ this.value + '); return false;" class="next">Next ></a>';
				return '<span class="disabled">Next ></span>';

			case 'prev':

				if (this.active)
					return '<a href="" onclick="viewPage('+ this.value + '); return false;" class="prev">< Prev</a>';
				return '<span class="disabled">< Prev</span>';

			case 'first':

				if (this.active)
					return '<a href="" onclick="viewPage('+ this.value + '); return false;" class="first">|<</a>';
				return '<span class="disabled">|<</span>';

			case 'last':

				if (this.active)
					return '<a href="" onclick="viewPage('+ this.value + '); return false;" class="last">>|</a>';
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
	$(window).hashchange(function() {

		if (window.location.hash)
			Paging.setPage(window.location.hash.substr(1));
		else
			Paging.setPage(1); // we dropped the initial page selection and need to run it manually
	});

	$(window).hashchange();
	
	
	// Show the pagination toolbars if enough elements are present
	if ((numResults/pageLimit)>1) {
		$(".toppagination")[0].style.display="block";
		$(".toppagination")[1].style.display="block";
	} else {
		$(".toppagination")[0].style.display="none";
		$(".toppagination")[1].style.display="none";		
	}
	

}
</script>
<div class="clear"></div>

<section id="content" class="grid_20 content"> <!-- <h3 style="margin-left: 8px">Search</h3>  -->

<div class="grid_6 ">
	<div class="searchform box">

		<form class="grid_5" action="/search">
			<input class="search" type="text"
				value="<%=query.getKeywordDisplay()%>" name="keyword"
				placeholder="Search" autocomplete="off" /> <input id="submit"
				type="submit" value="Search" />

			<%
				Iterator<String> facetsUsedHidden = query.getFacets().keySet()
						.iterator();
				while (facetsUsedHidden.hasNext()) {
					String facetName = facetsUsedHidden.next();
					String facetValue = query.getFacets().get(facetName);
			%>
			<input type="hidden" name="facet-<%=facetName%>"
				value="<%=facetValue%>">
			<%
				}
			%>
		</form>

		<%
			Iterator<String> facetsUsed = query.getFacets().keySet().iterator();
			while (facetsUsed.hasNext()) {
				String facetName = facetsUsed.next();
				String facetValue = query.getFacets().get(facetName);
		%>
		<div class="search-facet-selected">
			<a class="search-close"
				href="?<%=query.getURLParametersWithoutFacet(facetName)%>&amp;"></a>
			<%
				out.print(facetValue);
			%>
		</div>
		<%
			}

			if (resultSet.getSpellingSuggestedTerm() != null
					&& !resultSet.getSpellingSuggestedTerm().equals("")) {
				out.println("Did you mean <a href=\"/search?keyword="
						+ resultSet.getSpellingSuggestedTerm() + "\">"
						+ resultSet.getSpellingSuggestedTerm() + "</a> ?");
			}
			out.println("<br /><br /><b>" + resultSet.getNumberOfResults() + "</b>"
					+ " results were returned.<br/><br/>");
		%>
		<%
			if (resultSet.getNumberOfResults() > 0) {
		%>
		<h5>Refine by:</h5>

		<ul id="tree">
			<%
				List<FacetGroup> facetGroups = resultSet.getFacets();

					if (facetGroups != null) {

						for (int i = 0; i < facetGroups.size(); i++) {
							FacetGroup facetGroup = (FacetGroup) facetGroups.get(i);
							String fieldLabel = facetGroup.getFieldLabel();
							String field = facetGroup.getField();
							List<Facet> facets = facetGroup.getFacets();

							// Do not print out the facet for a field already faceting on
							if (!query.getFacets().containsKey(field)) {

								out.println("<li>" + fieldLabel + "<ul>");

								for (int j = 0; j < facets.size(); j++) {
									Facet facet = facets.get(j);

									out.print("<li><a href='?"
											+ query.getURLParametersWithExtraFacet(
													field, facet.getBand()) + "'>");
									out.print(facet.getBand() + "</a> ("
											+ facet.getOccurences() + ")</li>");

								}
								out.println("</ul></li>");
							}
						}
					}
			%>
		</ul>
		<%
			}
		%>
	</div>
</div>

	<div class="grid_13 container" id="pagination_container">

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
				out.println("<p class=\"box\">We couldn't find any items matching <b>"
						+ query.getKeywordDisplay() + "</b></p>");
				out.println("<p class=\"box\">Try <a href='/search'>browsing our items.</a></p>");

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
 


</section>


<jsp:include page="footer/footer.jsp" />



