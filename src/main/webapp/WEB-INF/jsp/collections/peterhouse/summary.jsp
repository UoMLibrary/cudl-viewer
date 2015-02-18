<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
	import="ulcambridge.foundations.viewer.model.*"%>
<%
	Collection collection = (Collection) request
			.getAttribute("collection");
%>

<div class="grid_10">

	<h1><%=collection.getTitle()%></h1>
	<div class="campl-column12">

		<div class="campl-column8">
			<blockquote class="cam-quote-mark">

				The volumes great, who so doth still peruse,<br /> And dailie
				turnes, and gazeth on the same,<br /> If that the fruicte thereof,
				he do not use,<br /> He reapes but toile, and never gaineth fame:<br />
				Firste reade, then marke, then practise that is good,<br /> For
				without use, we drinke but LETHE flood. <br /> <br /> <cite>
					Geffrey Whitney, <i>A Choice of Emblemes</i> (Leiden, 1586), p.
					171, dedicated to Andrew Perne.
				</cite>


			</blockquote>
		</div>
		<div class="campl-column4">
			<img class="collectionOrganisationalImage"
				src="/images/collectionsView/peterhouse.jpg" alt="Peterhouse Crest"
				width="150" height="225" />
		</div>
	</div>
	<div class="campl-column12">

		<p>Peterhouse (founded 1284) is the oldest of the Cambridge
			Colleges. Its founder, Hugh of Balsham, Bishop of Ely, bequeathed a
			number of books to the College on his death in 1286. The continuing
			generosity of members of Peterhouse built up a substantial library
			during the next two and a half centuries. A catalogue begun in 1418
			and maintained until 1481 gives details of over 450 manuscripts, more
			than two hundred of which survive today, overwhelming still in the
			College's possession. In addition, manuscripts were added by donors
			from the end of the fifteenth century until the mid-seventeenth
			century. A total of 276 medieval manuscripts belonging to Peterhouse
			are now on deposit in the University Library, where they may be
			consulted.</p>
		<p>
			As part of the process of recataloguing and preserving the College's
			collections, it has been decided to present highlights from the
			Peterhouse manuscripts in digital form. The first group of
			manuscripts to be digitised was the independent collection of
			sixteenth- and seventeenth-century part books of choral music, which
			are available through the <a href='http://www.diamm.ac.uk/'
				target='_blank'>Digital Image Archive of Medieval Music (DIAMM)</a>.
			It is now hoped to present some of the College's medieval manuscripts
			with appropriate commentary as part of the Cambridge Digital
			Collections. The first manuscript selected for this purpose is the
			Equatorie of the Planetis (Peterhouse Ms. 75.1). As funding becomes
			available, further manuscripts will be added to the online
			collection.
		</p>

		<!-- 
		Want to view items by subject or date? <br /> <a
			href="/search?facet-collection=Peterhouse+Manuscripts">Search the
			Peterhouse Manuscripts collection</a> <br /> <br />
-->
	</div>
</div>