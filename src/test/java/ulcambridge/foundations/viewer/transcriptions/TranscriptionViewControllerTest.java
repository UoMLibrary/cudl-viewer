package ulcambridge.foundations.viewer.transcriptions;

import java.io.IOException;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.ModelAndView;

import ulcambridge.foundations.viewer.transcriptions.TranscriptionViewController;

public class TranscriptionViewControllerTest extends TestCase {

    public void testHandleRequest() throws IOException {

        // Test Transcription not found case (empty Transcription URL)
        MockHttpServletRequest req1 = new MockHttpServletRequest();
        MockHttpServletResponse res1 = new MockHttpServletResponse();
        TranscriptionViewController c = new TestableTranscriptionViewController();
        ModelAndView mDoc = c.handleRequest("","", req1, res1);
        assertEquals(null, mDoc);
        assertEquals(
                res1.getContentAsString(),
                "<html><head>"
                        + "<link href=\"styles/style-transcription.css\" rel=\"stylesheet\" type=\"text/css\" />\n"
                        + "</head><body><div class=\"transcription\"> No transcription available for this image. </div></body></html>");

        // Test Transcription found case.
        // FIXME - Now transcription request also includes caching need
        // to rethink this test.
        /*
        MockHttpServletRequest req2 = new MockHttpServletRequest();
        MockHttpServletResponse res2 = new MockHttpServletResponse();
        ModelAndView m = c.handleRequest("http://www.newtonproject.sussex.ac.uk/","",
                req2, res2);
        assertEquals(null, m);
        assertEquals(
                res2.getContentAsString(),
                "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\"><html><head><meta content=\"text/html; charset=iso-8859-1\" http-equiv=\"Content-Type\" /><title>Extract from Three paragraphs on religion, with drafts (Normalized Version)</title><script type=\"text/JavaScript\" src=\"http://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/jquery.tooltip.js\" /><script type=\"text/JavaScript\" src=\"http://yui.yahooapis.com/combo?2.7.0/build/yahoo-dom-event/yahoo-dom-event.js&amp;2.7.0/build/animation/animation-min.js&amp;2.7.0/build/datasource/datasource-min.js&amp;2.7.0/build/element/element-min.js&amp;2.7.0/build/json/json-min.js&amp;2.7.0/build/charts/charts-min.js&amp;2.7.0/build/dragdrop/dragdrop-min.js&amp;2.7.0/build/container/container-min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/treeview-min-patched.js\" /><script type=\"text/JavaScript\" src=\"http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.12/jquery-ui.min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/tei-interactivity.js\" /><link type=\"text/css\" href=\"http://yui.yahooapis.com/combo?2.7.0/build/reset-fonts-grids/reset-fonts-grids.css&amp;2.7.0/build/base/base-min.css&amp;2.7.0/build/container/assets/skins/sam/container.css&amp;2.7.0/build/treeview/assets/skins/sam/treeview.css\" rel=\"stylesheet\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/assets/tree.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/navtree.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/texts.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/newton.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/jquery.tooltip.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/jquery-ui-1.8.12.custom.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/print.css\" rel=\"stylesheet\" type=\"text/css\" media=\"print\" /><link href=\"styles/style-transcription.css\" rel=\"stylesheet\" type=\"text/css\" />\n"
                        + "</head><body><div class=\"transcription\">\n"
                        + "<div class=\"transcription-credit\">Transcription by the <a target='_blank' href='http://www.newtonproject.sussex.ac.uk/'>Newton Project</a></div><div id=\"tei\"><span class=\"pagenumber\" id=\"p001r\"> &lt;1r&gt; </span> <div> <h2 id=\"hd1\" class=\"cent\">Our religion to God.</h2> <p id=\"par1\">God made the world &amp; governs it invisibly, &amp; hath commanded us <a id=\"l1\" />to love honour &amp; worship him &amp; no other God but him &amp; to do it without making any image <a id=\"l2\" />of him, &amp; not to name him idly &amp; without reverence, &amp; to honour our parents <a id=\"l3\" />masters &amp; governours, &amp; love our neighbours as our selves, &amp; to be tem<a id=\"l4\" />perate, modest, humble, just, &amp; peaceable, &amp; to be merciful even to bruit beasts.</p> <p id=\"par2\" /> </div> <div> <h2 id=\"hd2\" class=\"cent\">Our religion to Iesus Christ.</h2> <p id=\"par3\">Iesus Christ a true man born of a woman  was crucified by the Iews for teaching <a id=\"l5\" />them the truth, &amp; by the same power by which God gave life at first to every species of ani<a id=\"l6\" />mals being revived, he appeared to his disciples &amp; explained to them Moses &amp; the <a id=\"l7\" />Prophets concerning himself, as that he was the Sun of righteousness spoken of by Malachy, <a id=\"l8\" />the son of man &amp; the Messiah spoken of by Daniel, <img title=\"Symbol (dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (dot in a circle) in text\" /><span class=\"pagenumber-embed\"> &lt; insertion from lower down f 1r &gt; </span><img title=\"Symbol (dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (dot in a circle) in text\" /> God's servant David spoken of by Ezekiel, the Lord our righteousness spoken of by Ieremy, <a id=\"l9\" />the Ruler in Israel spoken of by Micah,<span class=\"pagenumber-embed\"> &lt; text from f 1r resumes &gt; </span> the servant of God &amp; lamb of God <a id=\"l10\" />&amp; Redeemer spoken of by Isaiah, the son of God &amp; the Holy one spoken of by <a id=\"l11\" />David, the seed of the woman &amp; the Prophet &amp; the Shiloh spoken of by Moses &amp;c. <a id=\"l12\" />And then he sent his disciples to teach others what he had taught them, &amp; is <a id=\"l13\" />gone into the heavens to receive a kingdom &amp; prepare a place for us, &amp; is <a id=\"l14\" />mystically said to sit at the right hand of God, that is, to be next to him in <a id=\"l15\" />dignity, &amp; is worshipped &amp; glorified as the Lamb of God, &amp; hath sent the <a id=\"l16\" />Holy Ghost to comfort us in his absence, &amp; will at length return &amp; reign <a id=\"l17\" />above in the  air (invisibly to mortals) till he hath raised up &amp; judged all the dead <a id=\"l18\" />(the saints in the first thousand years &amp; the rest afterwards) <img title=\"Symbol (thick black dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (thick black dot in a circle) in text\" /> &amp; sent the wicked to places suitable to their merits &amp; then he will give up <a id=\"l19\" />this kingdom to the father, <img title=\"Symbol (what may be the figure 2 in a circle, partially erased) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what may be the figure 2 in a circle, partially erased) in text\" /> &amp; carry the blessed (whom he hath merited by his <a id=\"l20\" />death &amp; redeemed with his blood) to the place or mansion which he is now preparing for <a id=\"l21\" />them. <img title=\"Symbol (what may be the figure 1 in a circle, deleted) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what may be the figure 1 in a circle, deleted) in text\" />  <img title=\"Symbol (what seems to be the figure 9 in a circle, deleted) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what seems to be the figure 9 in a circle, deleted) in text\" /> ffor in <a id=\"l22\" />God's house (which is the univers) are many mansions</p> <p id=\"par4\" /> </div> <div> <h2 id=\"hd3\" class=\"cent\">Our religion to the Church</h2> <p id=\"par5\">We enter into societies (called churches) not by birth as the Iews did but by the ceremonies of baptism &amp; <a id=\"l23\" /> confirmation, &amp; assemble weekly to worship God joyntly by prayers <a id=\"l24\" />&amp; praises, &amp; in our assemblies commemorate the death of Christ by breaking <a id=\"l25\" />of bread &amp; drinking of wine the symbols of his body &amp; blood, &amp; submit our causes to <a id=\"l26\" />our governours who in every city compose a board of Elders  with a President <a id=\"l27\" />elected by the citizens,  under whom are deacons to take care of the poor. And every particular church sends an Elder or Presbyter to <a id=\"l30\" />every Parish under its jurisdiction, to instruct &amp; govern the inhabitants. And by <a id=\"l31\" />communicatory letters from the President they joyne in worship with other cities <a id=\"l32\" />all which together compose the Church catholick. And this Church was illuminated <a id=\"l33\" />by the lamps of the seven Churches of Asia till the death of Iohn the Apostle &amp; <a id=\"l34\" />his disciples:  &amp; had authority to propagate what she received &amp; <a id=\"l35\" />only what she received by tradition from the Apostles &amp; Prophets, &amp; is to continue <a id=\"l36\" />till the times of the Gentiles be accomplished, &amp; then shall all Israel be saved.</p> </div> </div><div id=\"endnotes\" /><div id=\"notepanels\" /></div></div><div id=\"navigation\"></div></body></HTML>");

          */
    }

    class TestableTranscriptionViewController extends
            TranscriptionViewController {

        @Override
        protected String readContent(String url) throws IOException {
            return "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1 plus MathML 2.0//EN\" \"http://www.w3.org/TR/MathML2/dtd/xhtml-math11-f.dtd\"> <html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\"><head><meta content=\"text/html; charset=iso-8859-1\" http-equiv=\"Content-Type\" /><title>Extract from Three paragraphs on religion, with drafts (Normalized Version)</title><script type=\"text/JavaScript\" src=\"http://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/jquery.tooltip.js\" /><script type=\"text/JavaScript\" src=\"http://yui.yahooapis.com/combo?2.7.0/build/yahoo-dom-event/yahoo-dom-event.js&amp;2.7.0/build/animation/animation-min.js&amp;2.7.0/build/datasource/datasource-min.js&amp;2.7.0/build/element/element-min.js&amp;2.7.0/build/json/json-min.js&amp;2.7.0/build/charts/charts-min.js&amp;2.7.0/build/dragdrop/dragdrop-min.js&amp;2.7.0/build/container/container-min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/treeview-min-patched.js\" /><script type=\"text/JavaScript\" src=\"http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.12/jquery-ui.min.js\" /><script type=\"text/JavaScript\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/js/tei-interactivity.js\" /><link type=\"text/css\" href=\"http://yui.yahooapis.com/combo?2.7.0/build/reset-fonts-grids/reset-fonts-grids.css&amp;2.7.0/build/base/base-min.css&amp;2.7.0/build/container/assets/skins/sam/container.css&amp;2.7.0/build/treeview/assets/skins/sam/treeview.css\" rel=\"stylesheet\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/assets/tree.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/navtree.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/texts.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/newton.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/jquery.tooltip.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/jquery-ui-1.8.12.custom.css\" rel=\"stylesheet\" type=\"text/css\" /><link href=\"http://www.newtonproject.sussex.ac.uk/mainui/css/print.css\" rel=\"stylesheet\" type=\"text/css\" media=\"print\" /></head><body class=\"yui-skin-sam\"><div style=\"position:absolute; visibility:hidden; z-index:1000;\" id=\"overDiv\" /><div class=\"yui-t2\" id=\"doc2\"><div id=\"hd\"><p id=\"masthead\"><a href=\"http://www.newtonproject.sussex.ac.uk/prism.php?id=1\"><span id=\"mainlogotext\">The Newton Project</span><img alt=\"The Newton Project Logo\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/newton.png\" id=\"mainlogo\" /></a>"
                    + "</p></div><div id=\"bd\"><div id=\"yui-main\"><div class=\"yui-b\"><div class=\"yui-gc\"><div class=\"yui-u first\"><div class=\"maintext\"><!--start-text-container--><div id=\"text_container\"><div id=\"header\"><h1>Extract from Three paragraphs on religion, with drafts</h1><p class=\"author\">by Isaac Newton</p><p class=\"metadataContent\"><span class=\"metadataTitle\">Source:</span> Keynes Ms. 9, King's College, Cambridge, UK</p><p id=\"switcher\"><a href=\"/view/extract/diplomatic/THEM00009/start=p001r&amp;end=p001r\">Switch to diplomatic extract</a> <img alt=\"Explain the view differences\" src=\"/mainui/images/icons/help.png\" id=\"switcherHelpIcon\" /></p><p id=\"full_text_link\">Read the complete text at:<br /><a href=\"http://www.newtonproject.sussex.ac.uk/view/texts/normalized/THEM00009\">http://www.newtonproject.sussex.ac.uk/view/texts/normalized/THEM00009</a></p><div id=\"switcherHelp\"><p class=\"normal\">Diplomatic transcriptions offer a detailed representation of the document with minimal editorial intervention. All deletions and additions are rendered in the text and shorthand abbreviations have not been expanded. Switching to the diplomatic view of this text will:</p><ul><li>show 16 deletions</li><li>reveal 19 additions</li><li>not apply 9 editorial regularizations</li></ul></div><ul id=\"addmeta\"><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />Additional Metadata</span><ul><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />Hand List</span><ul><li>Holograph</li><li>with some characters in a different ink, apparently added later</li><li>and one heading added in pencil by an unknown later hand</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />Languages</span><ul><li>English</li><li>Latin</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />Revision History</span><ul><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />1 April 1998</span><ul><li>Transcribed by Stephen Snobelen</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />1 January 2001</span><ul><li>Catalogue information compiled by Rob Iliffe, Peter Spargo &amp; John Young</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />15 January 2002</span><ul><li>Checked against original by John Young</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />25 February 2002</span><ul><li>Tagged by John Young</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />25 October 2006</span><ul><li>Coding audited and updated to Newton v2.0 DTD by Michael Hawkins</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />25 February 2008</span><ul><li>Coding checked and updated to Newton v2.1 DTD by John Young</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />20 April 2009</span><ul><li>Updated to Newton V3.0 (TEI P5 Schema) by Michael Hawkins</li></ul></li><li class=\"expandable\"><span class=\"label\"><span class=\"ui-icon ui-icon-triangle-1-e\" />29 September 2011</span><ul><li>Catalogue exported to teiHeader by Michael Hawkins</li></ul></li></ul></li></ul></li></ul></div><div id=\"tei\"><span class=\"pagenumber\" id=\"p001r\"> &lt;1r&gt; </span> <div> <h2 id=\"hd1\" class=\"cent\">Our religion to God.</h2> <p id=\"par1\">God made the world &amp; governs it invisibly, &amp; hath commanded us <a id=\"l1\" />to love honour &amp; worship him &amp; no other God but him &amp; to do it without making any image <a id=\"l2\" />of him, &amp; not to name him idly &amp; without reverence, &amp; to honour our parents <a id=\"l3\" />masters &amp; governours, &amp; love our neighbours as our selves, &amp; to be tem<a id=\"l4\" />perate, modest, humble, just, &amp; peaceable, &amp; to be merciful even to bruit beasts.</p> <p id=\"par2\" /> </div> <div> <h2 id=\"hd2\" class=\"cent\">Our religion to Iesus Christ.</h2> <p id=\"par3\">Iesus Christ a true man born of a woman  was crucified by the Iews for teaching <a id=\"l5\" />them the truth, &amp; by the same power by which God gave life at first to every species of ani<a id=\"l6\" />mals being revived, he appeared to his disciples &amp; explained to them Moses &amp; the <a id=\"l7\" />Prophets concerning himself, as that he was the Sun of righteousness spoken of by Malachy, <a id=\"l8\" />the son of man &amp; the Messiah spoken of by Daniel, <img title=\"Symbol (dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (dot in a circle) in text\" /><span class=\"pagenumber-embed\"> &lt; insertion from lower down f 1r &gt; </span><img title=\"Symbol (dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (dot in a circle) in text\" /> God's servant David spoken of by Ezekiel, the Lord our righteousness spoken of by Ieremy, <a id=\"l9\" />the Ruler in Israel spoken of by Micah,<span class=\"pagenumber-embed\"> &lt; text from f 1r resumes &gt; </span> the servant of God &amp; lamb of God <a id=\"l10\" />&amp; Redeemer spoken of by Isaiah, the son of God &amp; the Holy one spoken of by <a id=\"l11\" />David, the seed of the woman &amp; the Prophet &amp; the Shiloh spoken of by Moses &amp;c. <a id=\"l12\" />And then he sent his disciples to teach others what he had taught them, &amp; is <a id=\"l13\" />gone into the heavens to receive a kingdom &amp; prepare a place for us, &amp; is <a id=\"l14\" />mystically said to sit at the right hand of God, that is, to be next to him in <a id=\"l15\" />dignity, &amp; is worshipped &amp; glorified as the Lamb of God, &amp; hath sent the <a id=\"l16\" />"
                    + "Holy Ghost to comfort us in his absence, &amp; will at length return &amp; reign <a id=\"l17\" />above in the  air (invisibly to mortals) till he hath raised up &amp; judged all the dead <a id=\"l18\" />(the saints in the first thousand years &amp; the rest afterwards) <img title=\"Symbol (thick black dot in a circle) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (thick black dot in a circle) in text\" /> &amp; sent the wicked to places suitable to their merits &amp; then he will give up <a id=\"l19\" />this kingdom to the father, <img title=\"Symbol (what may be the figure 2 in a circle, partially erased) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what may be the figure 2 in a circle, partially erased) in text\" /> &amp; carry the blessed (whom he hath merited by his <a id=\"l20\" />death &amp; redeemed with his blood) to the place or mansion which he is now preparing for <a id=\"l21\" />them. <img title=\"Symbol (what may be the figure 1 in a circle, deleted) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what may be the figure 1 in a circle, deleted) in text\" />  <img title=\"Symbol (what seems to be the figure 9 in a circle, deleted) in text\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/texts/symbol.gif\" alt=\"Symbol (what seems to be the figure 9 in a circle, deleted) in text\" /> ffor in <a id=\"l22\" />God's house (which is the univers) are many mansions</p> <p id=\"par4\" /> </div> <div> <h2 id=\"hd3\" class=\"cent\">Our religion to the Church</h2> <p id=\"par5\">We enter into societies (called churches) not by birth as the Iews did but by the ceremonies of baptism &amp; <a id=\"l23\" /> confirmation, &amp; assemble weekly to worship God joyntly by prayers <a id=\"l24\" />&amp; praises, &amp; in our assemblies commemorate the death of Christ by breaking <a id=\"l25\" />of bread &amp; drinking of wine the symbols of his body &amp; blood, &amp; submit our causes to <a id=\"l26\" />our governours who in every city compose a board of Elders  with a President <a id=\"l27\" />elected by the citizens,  under whom are deacons to take care of the poor. And every particular church sends an Elder or Presbyter to <a id=\"l30\" />every Parish under its jurisdiction, to instruct &amp; govern the inhabitants. And by <a id=\"l31\" />communicatory letters from the President they joyne in worship with other cities <a id=\"l32\" />all which together compose the Church catholick. And this Church was illuminated <a id=\"l33\" />by the lamps of the seven Churches of Asia till the death of Iohn the Apostle &amp; <a id=\"l34\" />his disciples:  &amp; had authority to propagate what she received &amp; <a id=\"l35\" />only what she received by tradition from the Apostles &amp; Prophets, &amp; is to continue <a id=\"l36\" />till the times of the Gentiles be accomplished, &amp; then shall all Israel be saved.</p> </div> </div><div id=\"endnotes\" /><div id=\"notepanels\" /></div><!--end-text-container--></div></div><div class=\"yui-u\"><div id=\"complementary\"><div id=\"related_texts\"><div id=\"similar_materials\"><h2>Material on similar topics</h2><ul><li><span class=\"quicktitle-record\">John Milton, <span class=\"item_link\"><a href=\"/view/texts/normalized/THEM00308\">Book I: Chapter 8</a></span>  [<em>Treatise on Christian Doctrine</em>, Vol. 1 (1825)]</span></li><li><span class=\"quicktitle-record\">John Milton, <span class=\"item_link\"><a href=\"/view/texts/normalized/THEM00299\">Front Matter (Dedication, Preliminary Observations, Table of Contents)</a></span>  [<em>Treatise on Christian Doctrine</em>, Vol. 1 (1825)]</span></li><li><span class=\"quicktitle-record\">John Milton, <span class=\"item_link\"><a href=\"/view/texts/normalized/THEM00314\">Book I: Chapter 14</a></span>  [<em>Treatise on Christian Doctrine</em>, Vol. 1 (1825)]</span></li><li><span class=\"quicktitle-record\">John Milton, <span class=\"item_link\"><a href=\"/view/texts/normalized/THEM00324\">Book I: Chapter 24</a></span>  [<em>Treatise on Christian Doctrine</em>, Vol. 2 (1825)]</span></li><li><span class=\"quicktitle-record\">Isaac Newton, <span class=\"item_link\"><a href=\"/view/texts/normalized/THEM00008\">Twelve articles on religion</a></span>  [KingsCollegeCambridge Keynes Ms. 8]</span></li></ul></div></div></div></div></div></div></div><div class=\"yui-b\" id=\"right_column\"><div id=\"search\"><form id=\"cse-search-box\" action=\"http://www.newtonproject.sussex.ac.uk/search\"><div><input value=\"016463761859239169897:7e7jb9e8q4w\" name=\"cx\" type=\"hidden\" /><input value=\"FORID:10\" name=\"cof\" type=\"hidden\" /><input value=\"UTF-8\" name=\"ie\" type=\"hidden\" /><input size=\"31\" name=\"q\" type=\"text\" id=\"search_field\" /><input value=\"Search\" name=\"sa\" type=\"submit\" id=\"search_button\" /></div></form></div><div id=\"navigation\"> <ul> <li><a href=\"/prism.php?id=1\">Home</a></li> <li><a href=\"/prism.php?id=141\">Take Tour</a></li> <li>Electronic Texts <ul> <li>Newton's Works <ul> <li><a href=\"/prism.php?id=43\">Browse All</a></li> <li>Religious Writings <ul> <li><a href=\"/prism.php?id=75\">On the Origins of Science and Civilization</a></li> <li><a href=\"/prism.php?id=74\">On Prophecy, Revelation and the End of Times</a></li> <li><a href=\"/prism.php?id=76\">On Christ and God</a></li> <li><a href=\"/prism.php?id=73\">On the Early Church</a></li> <li><a href=\"/prism.php?id=44\">All</a></li>  </ul> </li> <li><a href=\"/prism.php?id=45\">Scientific Papers</a></li> <li><a href=\"/prism.php?id=49\">Notebooks</a></li> <li><a href=\"/prism.php?id=46\">Alchemical Writings</a></li>  </ul> </li> <li>Browse texts <ul> <li><a href=\"/prism.php?id=135\">by author</a></li> <li><a href=\"/prism.php?id=136\">by subject</a></li>  </ul> </li> <li>About our Electronic Texts <ul> <li><a href=\"/prism.php?id=29\">What is an Electronic Edition?</a></li> <li><a href=\"/prism.php?id=30\">"
                    + "Our Editorial Policies</a></li> <li><a href=\"/prism.php?id=51\">Our Production Processes</a></li> <li><a href=\"/prism.php?id=52\">Tagging &amp; Transcription Guidelines</a></li>  </ul> </li>  </ul> </li> <li>Catalogue <ul> <li><a href=\"/prism.php?id=83\">Search</a></li> <li>Browse <ul> <li><a href=\"/prism.php?id=82\">by Category</a></li> <li><a href=\"/prism.php?id=94\">by Location</a></li>  </ul> </li> <li><a href=\"/prism.php?id=86\">Abbreviations used in the Catalogue</a></li>  </ul> </li> <li>Newton's Life and Character <ul> <li><a href=\"/prism.php?id=15\">His Life &amp; Work at a Glance</a></li> <li><a href=\"/prism.php?id=40\">His Personal Life</a></li> <li>Views of Newton's Personality <ul> <li><a href=\"/prism.php?id=41\">18th Century</a></li> <li><a href=\"/prism.php?id=106\">19th Century</a></li>  </ul> </li> <li>Controversies <ul> <li><a href=\"/prism.php?id=111\">Optical Theories &amp; Correspondence</a></li>  </ul> </li> <li><a href=\"/prism.php?id=90\">Bibliography</a></li>  </ul> </li> <li>His Library <ul> <li><a href=\"/prism.php?id=59\">About Newton's Library</a></li> <li><a href=\"/prism.php?id=88\">Alchemical Texts</a></li> <li><a href=\"/prism.php?id=87\">Religious Books</a></li> <li><a href=\"/prism.php?id=89\">Mint-Related Texts</a></li>  </ul> </li> <li>History of his Papers <ul> <li><a href=\"/prism.php?id=20\">1727-1872</a></li> <li><a href=\"/prism.php?id=21\">The Portsmouth Papers</a></li> <li><a href=\"/prism.php?id=23\">The Sotheby Sale</a></li> <li><a href=\"/prism.php?id=19\">Newton-related Papers of John Maynard Keynes</a></li> <li><a href=\"/prism.php?id=22\">Other Attempts to Publish Newton's Papers</a></li>  </ul> </li> <li>About Us <ul> <li><a href=\"/prism.php?id=26\">The Newton Project</a></li> <li><a href=\"/prism.php?id=27\">Our Goals</a></li> <li><a href=\"/prism.php?id=139\">Our Progress</a></li> <li><a href=\"/prism.php?id=28\">History of the Project</a></li> <li><a href=\"/prism.php?id=18\">Our Funding</a></li> <li><a href=\"/prism.php?id=24\">Staff and Editorial Board</a></li> <li><a href=\"/prism.php?id=32\">Acknowledgments</a></li> <li><a href=\"/prism.php?id=16\">Collaborative Projects</a></li>  </ul> </li> <li><a href=\"/prism.php?id=25\">Support Us</a></li> <li>Links <ul> <li><a href=\"/prism.php?id=137\">About</a></li> <li><a href=\"/prism.php?id=96\">Digital Libraries &amp; Archives</a></li> <li><a href=\"/prism.php?id=93\">Other Editorial Projects</a></li> <li><a href=\"/prism.php?id=98\">Electronic Journals</a></li> <li><a href=\"/prism.php?id=100\">Other Material about Newton</a></li> <li><a href=\"/prism.php?id=101\">Other Figures in the History of Science</a></li> <li><a href=\"/prism.php?id=102\">History of Science Sites</a></li> <li><a href=\"/prism.php?id=103\">Newton's Writings on the Web</a></li>  </ul> </li>  </ul> </div></div></div><div id=\"ft\"><div id=\"sponsors\"><p class=\"label\">Sponsored by:</p><ul><li id=\"sussex_link\"><a href=\"http://www.sussex.ac.uk/\"><img alt=\"\" height=\"30\" width=\"134\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/sponsors/US.png\" /></a></li><li id=\"ahrc_link\"><a href=\"http://www.ahrc.ac.uk/\"><img alt=\"\" height=\"34\" width=\"126\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/sponsors/ahrc.png\" /></a></li><li id=\"jisc_link\"><a href=\"http://www.jisc.ac.uk/\"><img alt=\"\" height=\"36\" width=\"67\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/sponsors/jisc.png\" /></a></li><li id=\"cordis_link\"><a href=\"http://cordis.europa.eu/fp7/ict/home_en.html\"><img alt=\"\" height=\"36\" width=\"151\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/sponsors/cordis.png\" /></a></li><li id=\"rs_link\"><a href=\"http://www.royalsoc.ac.uk\"><img alt=\"\" height=\"36\" width=\"154\" src=\"http://www.newtonproject.sussex.ac.uk/mainui/images/sponsors/rs.png\" /></a></li></ul></div><div id=\"contact\"><p><strong>?? 2012 The Newton Project</strong></p><p>Professor Rob Iliffe <br />Director, AHRC Newton Papers Project</p><p>Scott Mandelbrote, <br />Fellow &amp; Perne librarian, Peterhouse, Cambridge</p><p>University of Sussex, East Sussex - BN1 9SH -<br /><strong>tel:</strong>+44 (0)1273 872868 - <strong>fax:</strong> +44 (0)1273 623246 - <a href=\"mailto:newtonproject@sussex.ac.uk\">newtonproject@sussex.ac.uk</a></p></div></div></div></body></html>";
        }

        @Override
        protected boolean isAllowedURL(String url) {
            return true;
        }
    }

}
