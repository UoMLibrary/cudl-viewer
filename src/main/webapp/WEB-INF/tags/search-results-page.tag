<%@tag description="Base search results page" pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %>

<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@taglib prefix="json" uri="http://www.atg.com/taglibs/json" %>

<%@taglib prefix="cudl" tagdir="/WEB-INF/tags" %>
<%@taglib prefix="cudlfn" uri="/WEB-INF/cudl-functions.tld" %>

<%@attribute name="title" required="true" type="java.lang.String" %>
<%@attribute name="queryInfo" required="true" fragment="true" %>
<%@attribute name="resultInfo" required="false" fragment="true" %>
<%@attribute name="queryHelp" required="false" fragment="true" %>

<cudl:generic-page pagetype="ADVANCED_SEARCH_RESULTS" title="${title}">
	<jsp:attribute name="pageData">
		<cudl:default-context>
			<json:property name="resultCount" value="${results.numberOfResults}"/>
			<json:property name="queryString" value="${queryString}"/>
		</cudl:default-context>
	</jsp:attribute>

	<jsp:body>
		<cudl:nav activeMenuIndex="${2}" displaySearch="true" title="${title}"/>

		<div class="campl-row campl-content campl-recessed-content">
			<div class="campl-wrap clearfix">
				<div class="campl-main-content" id="content">
					<div class="campl-column4 campl-secondary-content">

						<div class="searchform box">

							<div class="campl-content-container">
								<jsp:invoke fragment="queryInfo"/>

								<c:forEach items="${form.facets}" var="facet">
									<div class="search-facet-selected">
										<a class="search-close" href="?${fn:escapeXml(cudlfn:urlParamsWithoutFacet(form, facet.key))}" title="Remove">
											in <b><span><c:out value="${facet.value}"/></span></b> (<c:out value="${facet.key}"/>) &cross;
										</a>
									</div>
								</c:forEach>

								<c:if test="${not empty results.spellingSuggestedTerm}">
									Did you mean
									<a href="/search?keyword=${cudlfn:uriEnc(results.spellingSuggestedTerm)}">
										<c:out value="${results.spellingSuggestedTerm}"/>
									</a>
								</c:if>

								<c:choose>
									<c:when test="${empty resultInfo}">
										<cudl:search-result-info results="${results}"/>
									</c:when>
									<c:otherwise>
										<jsp:invoke fragment="resultInfo"/>
									</c:otherwise>
								</c:choose>
							</div>

							<c:if test="${results.numberOfResults > 0}">
								<div class="campl-content-container">
									<h5>Refine by:</h5>

									<ol id="tree" class="campl-unstyled-list">
										<c:forEach items="${results.facets}" var="facetGroup">
											<%-- Do not show a facet for a field we're already faceting on --%>
											<c:if test="${empty form.facets[facetGroup.field]}">
												<li>
													<%-- FIXME: Add these arrows in CSS instead --%>
													<strong>
														<span>▾</span> <c:out value="${facetGroup.fieldLabel}"/>
													</strong>
													<ul class="campl-unstyled-list">
														<c:forEach items="${facetGroup.facets}" var="facet">
															<li>
																<a href="?${fn:escapeXml(cudlfn:urlParamsWithFacet(form, facetGroup.field, facet.band))}">
																	<c:out value="${facet.band}"/>
																</a>
																(<c:out value="${facet.occurences}"/>)
															</li>
														</c:forEach>
													</ul>
												</li>
											</c:if>
										</c:forEach>
									</ol>
								</div>
							</c:if>
						</div>
					</div>

					<div class="campl-column8 camp-content">
						<c:if test="${empty results.results}">
							<div class="searchexample campl-content-container">
								<c:choose>
									<c:when test="${empty queryHelp}">
										<cudl:search-no-results/>
										<cudl:search-examples/>
									</c:when>
									<c:otherwise>
										<jsp:invoke fragment="queryHelp"/>
									</c:otherwise>
								</c:choose>
							</div>
						</c:if>


						<!-- start of list -->
						<div id="collections_carousel" class="collections_carousel">
						</div>
						<!-- end of list -->
						<div class="pagination toppagination"></div>
					</div>
				</div>
			</div>
		</div>
	</jsp:body>
</cudl:generic-page>