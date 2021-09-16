<%@page autoFlush="true" %>

<%@taglib prefix="cudl" tagdir="/WEB-INF/tags" %>


<cudl:generic-page pagetype="STANDARD" title="Privacy Policy">
    <cudl:nav activeMenuIndex="${4}" displaySearch="true" subtitle="Privacy Policy"/>

    <div class="campl-row campl-content campl-recessed-content">
        <div class="campl-wrap clearfix">
            <cudl:about-nav />
            <div class="campl-column8  campl-main-content" id="content">
                <div class="campl-content-container">
                    <h2>Cambridge Digital Library Privacy Policy</h2>
                    <hr class="cam-teaser-divider campl-column12">
                    <h5>My Library Users</h5>
                    <p>Users who log into the 'My Library' section, have a unique anonymised identifier stored in association
                    with their bookmarked items.  This enables unique accounts to store a list of bookmarked items that
                        they can view and manage when they log into this section.</p>

                    <p>They also have an one-way hash encoded and anonymised version of their email
                        address stored in order to allow My Library users to migrate their stored bookmarks to a new account, if required.</p>

                    <p>They can request that their information be deleted by emailing <a href="mailto:cudl-admin@lib.cam.ac.uk">
                    cudl-admin@lib.cam.ac.uk</a>.
                    </p>
                    <h5>University Library Privacy Policy</h5>
                    <p>More details can be found on the <a href="http://www.lib.cam.ac.uk/privacy-policy" target="_blank">
                        Cambridge University Library privacy policy page</a>.</p>

                </div>
            </div>
        </div>
    </div>
</cudl:generic-page>
