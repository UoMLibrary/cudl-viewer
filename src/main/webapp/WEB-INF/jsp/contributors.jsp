<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib prefix="c" 
       uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="header/header-full.jsp" />
<jsp:include page="header/nav.jsp">
	<jsp:param name="activeMenuIndex" value="3" />
	<jsp:param name="displaySearch" value="true" />
	<jsp:param name="subtitle"
		value="Contributors to the Cambridge Digital Library" />
</jsp:include>


<div class="campl-row campl-content campl-recessed-content">
	<div class="campl-wrap clearfix">

		<!-- side nav -->
		<div class="campl-column3">
			<div class="campl-tertiary-navigation">
				<div class="campl-tertiary-navigation-structure">
					<ul class="campl-unstyled-list campl-vertical-breadcrumb">
						<li><a href="/">Cambridge Digital Library<span
								class="campl-vertical-breadcrumb-indicator"></span></a></li>
					</ul>
					<ul
						class="campl-unstyled-list campl-vertical-breadcrumb-navigation">
						<li class="campl-selected"><a href="/about/">About</a>
							<ul
								class='campl-unstyled-list campl-vertical-breadcrumb-children'>
								<li><a href="/about/">Introducing the Cambridge Digital
										Library</a></li>
								<li><a href="/news/">News</a></li>
								<li><a href="/contributors/">Contributors</a></li>
								<li><a href="/terms/">Terms & Conditions</a></li>
							</ul></li>

					</ul>
				</div>
			</div>
		</div>


		<div class="campl-column8  campl-main-content" id="content">
			<div class="campl-content-container">
			
			
			<div id="contributorsDiv" contenteditable="true">				
		        <c:import charEncoding="UTF-8" url="/html/contributors.html" /> 
			</div>
			

			</div>
		</div>
	</div>
</div>

<jsp:include page="editor.jsp" >
  <jsp:param name='dataElements' value='contributorsDiv'/>
  <jsp:param name='filenames' value='contributors.html'/>
</jsp:include>

<jsp:include page="header/footer-full.jsp" />

