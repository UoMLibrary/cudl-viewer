<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<jsp:include page="header/header-login.jsp" />
<jsp:include page="header/nav-search.jsp">
	<jsp:param name="activeMenuIndex" value="1" />
	<jsp:param name="displaySearch" value="true" />
</jsp:include>

<div class="grid_20">
	<div class="clear"></div>

	<section id="content" class="grid_20 content ">

		<div class="grid_20">
			<h3>My Library</h3>
			Login to create or view your collection of bookmarks. <br />

			<div id="error">${error}</div>
			<br />

			<!-- Simple OpenID Selector -->
			<form action="/j_spring_openid_security_check" method="post"
				id="openid_form">
				<input type="hidden" name="action" value="verify" />
				<fieldset>
					<legend>Sign-in or Create New Account</legend>
					<div id="openid_choice">
						<p>Please click your account provider:</p>
						<div id="openid_btns"></div>
						<br />
						<br />
					</div>
					<div id="openid_input_area"> 
				<input id="openid_identifier" name="openid_identifier" type="text" value="http://" /> 
				<input id="openid_submit" type="submit" value="Sign-In"/> 
			</div>
			<noscript> 
				<p>OpenID is service that allows you to log-on to many different websites using a single indentity.
				Find out <a href="http://openid.net/what/">more about OpenID</a> and <a href="http://openid.net/get/">how to get an OpenID enabled account</a>.</p>
			</noscript>  
				</fieldset>
			</form>
			<!-- /Simple OpenID Selector -->

		</div>
</div>
<jsp:include page="footer/footer.jsp" />