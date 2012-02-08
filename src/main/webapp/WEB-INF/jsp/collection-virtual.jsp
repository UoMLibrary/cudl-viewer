<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" import="ulcambridge.foundations.viewer.model.*, java.util.Iterator"%>
<jsp:include page="header/header-full.jsp" />
<jsp:include page="header/nav-browse.jsp" />
<jsp:include page="header/nav-browse-collections.jsp" />

<% Collection collection = (Collection) request.getAttribute( "collection" ); %>
<script type="text/javascript">
	/*	function pageinit() {
	 var collections_carousel = new glow.widgets.Carousel("#collections_carousel", {
	 loop : true,
	 size : 3,
	 step : 3,
	 vertical : true,
	 pageNav : true
	 });
	 }
	 */
</script>

<div class="clear"></div>

<section id="content" class="grid_20 content">


<jsp:include page="<%=collection.getSummary() %>" />

<div class="grid_20">

	<% 
	   Iterator<Item> items = collection.getItems().iterator();
	   
	   while(items.hasNext()) {
		   Item item = items.next();
		   
			String imageDimensions = "";			

			if (item.getThumbnailOrientation().equals("portrait")) {
				imageDimensions += " width='140px'  height='185px'";
			} else if (item.getThumbnailOrientation().equals("landscape")) {
				imageDimensions += " width='185px' height='140px' ";
			}
			
		   out.print("<div class='grid_9'><a href='/view/"+item.getId()+"/'><img class='collections_carousel_image' "+
				   "src='"+item.getThumbnailURL()+"' "+imageDimensions+" "+
				   "alt='"+item.getId()+"' > </a>\n ");
		   out.print("<h5>"+item.getTitle()+" ("+item.getShelfLocator()+")</h5> " +
				   item.getAbstractShort()+" ... <a href='/view/"+item.getId()+"/'>more</a> "+
				    "</div>\n\n");
	   }
	
	%>
	


</div>

<jsp:include page="<%=collection.getSponsors() %>" />

</section>

<jsp:include page="footer/footer.jsp" />



