package ulcambridge.foundations.viewer;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import ulcambridge.foundations.viewer.exceptions.ResourceNotFoundException;
import ulcambridge.foundations.viewer.model.Item;
import ulcambridge.foundations.viewer.model.Properties;

/**
 * Controller for viewing iiif metadata
 *
 * @author jennie
 *
 */
@Controller
@RequestMapping("/iiif")
public class IIIFViewController {

    protected final Log logger = LogFactory.getLog(getClass());
    private final ItemFactory itemFactory;

    @Autowired
    public IIIFViewController(
        ItemFactory itemFactory, @Value("${rootURL}") URI rootUrl) {

        Assert.notNull(itemFactory);
        Assert.notNull(rootUrl);

        this.itemFactory = itemFactory;

    }

    // on path /iiif/{docId}.json
    @RequestMapping(value = "/{docId}.json")
    public ModelAndView handleIIIFRequest(@PathVariable("docId") String docId, HttpServletRequest request, HttpServletResponse response) throws JSONException {

        // force docID to uppercase
        docId = docId.toUpperCase();

        //Get services
        String servicesURL = Properties.getString("services");
        if (servicesURL.startsWith("//")) {
            servicesURL = request.getScheme() + ":"+servicesURL;
        }
        
        Item item = itemFactory.getItemFromId(docId);
        if (item != null && item.getIIIFEnabled()) {

            String baseURL = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
            IIIFPresentation pres = new IIIFPresentation(item, baseURL, servicesURL);
            JSONObject presJSON = pres.outputJSON();

            writeJSONOut(presJSON, response);

            return null;

        } else {
            throw new ResourceNotFoundException();
        }

    }

    private void writeJSONOut(JSONObject json, HttpServletResponse response)
            throws JSONException {

        // Write out JSON file.
        response.setContentType("application/json");
        PrintStream out = null;
        try {
            out = new PrintStream(new BufferedOutputStream(
                    response.getOutputStream()), true, "UTF-8");
            out.print(json.toString(1));
            out.flush();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                out.close();
            } catch (Exception e) {
            }
        }
    }

}
