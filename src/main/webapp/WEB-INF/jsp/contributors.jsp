<%@page autoFlush="true" %>

<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="cudl" tagdir="/WEB-INF/tags" %>


<cudl:generic-page pagetype="STANDARD">
    <jsp:attribute name="pageData">
        <cudl:default-context>
            <cudl:context-editable-areas>
                <cudl:editable-area id="contributorsDiv" filename="contributors.html"/>
            </cudl:context-editable-areas>
        </cudl:default-context>
    </jsp:attribute>

    <jsp:body>
        <cudl:nav activeMenuIndex="${4}" displaySearch="true"
                  subtitle="Contributors to the Cambridge Digital Library"/>

        <div id="main_content" class="campl-row campl-content campl-recessed-content">
            <div class="campl-wrap clearfix">
                <cudl:about-nav />
                <div class="campl-column8  campl-main-content" id="content">
                    <div class="campl-content-container">
                        <div id="contributorsDiv">
                            <c:import charEncoding="UTF-8" url="${contentHTMLURL}/contributors.html" />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </jsp:body>
</cudl:generic-page>
