package ulcambridge.foundations.viewer.pdf;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.layout.element.Div;
import com.itextpdf.layout.element.Image;
import org.json.JSONObject;
import ulcambridge.foundations.viewer.model.Item;

import javax.servlet.http.HttpServletResponse;
import java.net.MalformedURLException;

public class SinglePagePdf {

    private final String IIIFImageServer;
    private final BasicTemplatePdf basicTemplatePdf;

    public SinglePagePdf(String IIIFImageServer, String baseURL,
                         String headerText, int[] pdfColour,
                         String[] urlsForFontZips, String defaultFont) throws MalformedURLException {
        this.IIIFImageServer = IIIFImageServer;
        this.basicTemplatePdf = new BasicTemplatePdf(baseURL, headerText, pdfColour, urlsForFontZips, defaultFont);
    }

    public void writePdf(Item item, String page, HttpServletResponse response) {

        try {

            JSONObject pageJSON = item.getJSON().getJSONArray("pages").getJSONObject(Integer.parseInt(page) - 1);
            String iiifImageURL = pageJSON.getString("IIIFImageURL");

            String imageURL = IIIFImageServer + iiifImageURL + "/full/,1000/0/default.jpg";
            if (pageJSON.getInt("imageWidth") > pageJSON.getInt("imageHeight")) {
                imageURL = IIIFImageServer + iiifImageURL + "/full/1000,/0/default.jpg";
            }
            Image image = new Image(ImageDataFactory.create(imageURL));

            Div div = new Div();
            div.add(image.setMargins(10f, 0f, 30f, 0f)
                .scaleToFit(PageSize.A4.getWidth() - 60f, PageSize.A4.getHeight() - 220f));

            basicTemplatePdf.writePdf(item, div, response);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
