<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" 
import="java.net.URLEncoder, ulcambridge.foundations.viewer.model.*"%>
<!DOCTYPE html>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/> 
<%!
public String prepareForMetaTag(String input) {
	
	// replacing double quotes with single quotes 
	String output = input.replaceAll("\"", "'");
	
	// remove [ or ]
	output = output.replaceAll("\\[|\\]", "");
	
	return output;	
}
%>
<%
	String requestURL = request.getAttribute("requestURL").toString();
	String encodedRequestURL = URLEncoder.encode(requestURL, "UTF-8");
	String thumbnailURL = request.getAttribute("thumbnailURL").toString();
	Collection collection = (Collection) request.getAttribute("organisationalCollection");
	Collection parentCollection = (Collection) request.getAttribute("parentCollection");
	String collectionURL = "";
	String collectionTitle = "";
	String parentCollectionURL = "";
	String parentCollectionTitle = "";
	
	if (collection!=null) {
		collectionURL = collection.getURL();
		collectionTitle = collection.getTitle();
	}
	
	if (parentCollection!=null) {
		parentCollectionURL = parentCollection.getURL();
		parentCollectionTitle = parentCollection.getTitle();
	}
	
	// For use in meta tags and to aid search. 
	String metaItemAbstract = prepareForMetaTag(request.getAttribute("itemAbstract").toString());
	String metaItemTitle = prepareForMetaTag(request.getAttribute("itemTitle").toString());
	String metaItemAuthors = prepareForMetaTag(request.getAttribute("itemAuthors").toString());
	String metaRequestURL = requestURL.replaceFirst(request.getAttribute("docId")+"/"+".*$", request.getAttribute("docId").toString());
	
%>

<!--  google webmaster tools -->
<meta name="google-site-verification" content="FnLk7ALqNV0pIE7sbtHGY7D2V6cTtQVRQvYFFv5SZIU" />

<!-- page metadata tags -->
<title><%=collectionTitle%> : ${itemTitle}</title>
<meta property="schema:url" content="<%=metaRequestURL%>" />
<meta property="schema:name" content="<%=collectionTitle%> : <%=metaItemTitle%>" />
<meta name="description" property="schema:description" content="<%=metaItemAbstract%>" />
<meta name="keywords" property="schema:keywords" content="<%=metaItemAuthors%>" />
<meta property="schema:thumbnailUrl" content="<%=thumbnailURL%>" /> 

<jsp:include page="includes.jsp" />

<link rel="stylesheet" type="text/css" href="/scripts/extjs/resources/css/ext-partial-gray.css" />
<link rel="stylesheet" type="text/css" href="/styles/style-document.css" />
<link rel="stylesheet" type="text/css" href="/styles/style-document-thumbnails.css" />
<link rel="stylesheet" type="text/css" href="/styles/treestyler.css" media="screen" />

<script type="text/javascript">

	cudl.JSONURL = '${jsonURL}';
	cudl.JSONTHUMBURL = '${jsonThumbnailsURL}';
	cudl.pagenum = ${page};
	cudl.docId = '${docId}';
	cudl.docURL = '${docURL}';
	cudl.proxyURL = '${proxyURL}';
	
	// Read in Attributes
	cudl.collectionURL = "<%=collectionURL%>";
	cudl.collectionTitle = "<%=collectionTitle%>";	
	cudl.parentCollectionURL = "<%=parentCollectionURL%>";
	cudl.parentCollectionTitle = "<%=parentCollectionTitle%>";	
	cudl.itemTitle = "${itemTitle}";
	cudl.itemAuthors = ${itemAuthors};
	cudl.itemAuthorsFullForm = ${itemAuthorsFullform}	

</script>

<script type="text/javascript" src="/scripts/extjs/ext-all.js"></script>
<script type="text/javascript" src="/scripts/cudl-docData.js"></script>
<script type="text/javascript" src="/scripts/cudl-docViewport.js"></script>
<script type="text/javascript" src="/scripts/cudl-docView.js"></script>
<script type="text/javascript" src="/scripts/seadragon-min.js"></script>
<script type="text/javascript" src="/scripts/cudl-document.js"></script>

</head>
<body>

<!--  hidden section for the search engines to index -->
<div style="display:none">
  <h1><%=metaItemTitle%></h1>
  <h2><%=metaItemAuthors%></h2>
  <h2><%=collectionTitle%></h2>  
  <p><%=metaItemAbstract%></p>
</div>


	<div id="north">
 
		<header id="globalMasthead" style="width:100%; height:45px">        
                <a id="identifier" class="grid_4 alpha" href="http://www.cam.ac.uk" title="University of Cambridge">
                    University of Cambridge
                </a>
                
                <span class="header-title"><a href="/" title="Cambridge Digital Library">Cambridge Digital Library</a></span>
                <a id="libraryLogo" class="grid_4 alpha" title="Cambridge University Library" href="http://www.lib.cam.ac.uk"></a>
            </header>

		<!-- end #globalMasthead -->		
		<jsp:include page="nav-browse-document.jsp" />
		</div>
		