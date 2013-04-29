<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ page import="ulcambridge.foundations.viewer.forms.*"%>
<jsp:include page="header/header-full.jsp" />
<jsp:include page="header/nav-search.jsp" />

<div class="clear"></div>
<%
	SearchForm form = (SearchForm) request.getAttribute("form");
%>

<section id="content" class="grid_20 content">
	<h4 style="margin-left: 8px">Advanced Search</h4>

	<div class="grid_18">
		<div class="advancedsearchform box">

			<form:form commandName="searchForm" class="grid_17" method="GET"
				action="/search/advanced/results">

				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="keyword">Keywords</form:label>
					</div>
					<div class="grid_13">
						<span class="hint--right"
							data-hint="Search keywords in metadata or transcriptions"><form:input
								path="keyword" size="45" type="text" value="" name="keyword"
								placeholder="Search" /></span> <br /> <br />
					</div>
				</div>

				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="fullText">Full Text</form:label>
					</div>
					<div class="grid_8">
						<span class="hint--right" data-hint="Search transcription data"><form:input
								path="fullText" type="text" size="45" value="" name="fullText" /></span>
						<br />
						<form:label path="excludeText"> &nbsp; excluding </form:label>
						<span class="hint--right"
							data-hint="Exclude transcription results that mention these words"><form:input
								path="excludeText" type="text" size="35" value=""
								name="excludeText" /></span> <br /> <br />
					</div>
					<div class="grid_6">
						<span class="hint--right" data-hint="Applies to full text search"><form:radiobutton
								path="textJoin" class="radiobutton" type="radio" value="and"
								name="textJoin" /> All of these words<br /> <form:radiobutton
								path="textJoin" class="radiobutton" type="radio" value="or"
								name="textJoin" /> Any of these words </span><br /> <br />
					</div>
				</div>
				
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="shelfLocator">Classmark</form:label>
					</div>
					<div class="grid_14">

						<span class="hint--right" data-hint="e.g. MS Add.3996"><form:input
								path="shelfLocator" type="text" size="35" value="" name="shelfLocator" /></span>
						<br /> 
					</div>
				</div>
			
				
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="title">Title</form:label>
					</div>
					<div class="grid_14">
						<span class="hint--right"
							data-hint="Search for titles that includes these words, e.g. Letter"><form:input
								path="title" type="text" size="35" value="" name="title" /></span> <br />
					</div>
				</div>
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="author">Author</form:label>
					</div>
					<div class="grid_14">
						<span class="hint--right"
							data-hint="Search for items by this person, e.g. Darwin"><form:input
								path="author" type="text" size="35" value="" name="author" /> <br /></span>
					</div>
				</div>
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="subject">Subject</form:label>
					</div>
					<div class="grid_14">
						<span class="hint--right"
							data-hint="Search for items about this subject, e.g. Mathematics"><form:input
								path="subject" type="text" size="35" value="" name="subject" /></span> <br />
					</div>
				</div>
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="location">Location</form:label>
					</div>
					<div class="grid_14">
						<span class="hint--right"
							data-hint="Search for items related to a specific place, e.g. London"><form:input
								path="location" type="text" size="35" value="" name="location" /></span> <br />
					</div>
				</div>
				<div class="grid_17">
					<div class="grid_2">
						<form:label class="right" path="yearStart">Year</form:label>
					</div>
					<div class="grid_14">
						<span class="hint--right"
							data-hint="Limit results to this range of years"> <form:input
								path="yearStart" type="text" value="" name="yearStart" /> <form:label
								path="yearEnd"> to </form:label> <form:input path="yearEnd"
								type="text" value="" name="yearEnd" />
						</span> <br /> <br />
					</div>
				</div>
				<div class="grid_17">
					<div class="grid_16">
						<input id="submit" type="submit" value="Submit" /> <input
							id="reset" type="reset" value="Reset" />
					</div>

				</div>
			</form:form>

			<div class="altsearchlink grid_17">
				<form:form commandName="searchForm" action="/search" method="GET">

					<input type="hidden" value="<%=form.getKeyword()%>" name="keyword" />

					<input class="altsearchlink" type="submit"
						value="back to simple search" />

					<br />
					<br />
				</form:form>
			</div>


		</div>
	</div>

	<div class="grid_13 container" id="pagination_container">

		<div class="pagination toppagination"></div>
		<!-- start of list -->
		<div id="collections_carousel" class="collections_carousel"></div>
		<!-- end of list -->
		<div class="pagination toppagination"></div>

	</div>



</section>


<jsp:include page="footer/footer.jsp" />



