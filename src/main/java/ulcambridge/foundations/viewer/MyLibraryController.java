package ulcambridge.foundations.viewer;

import org.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import ulcambridge.foundations.viewer.dao.BookmarkDao;
import ulcambridge.foundations.viewer.dao.ItemsDao;
import ulcambridge.foundations.viewer.exceptions.TooManyBookmarksException;
import ulcambridge.foundations.viewer.model.Bookmark;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.List;

@Controller
@RequestMapping("/mylibrary")
public class MyLibraryController {
    private final ItemsDao itemDAO;
    private final BookmarkDao bookmarkDao;

    @Autowired
    public MyLibraryController(ItemsDao itemDAO,
                               BookmarkDao bookmarkDao) {
        Assert.notNull(itemDAO, "itemDAO is required");
        Assert.notNull(bookmarkDao, "bookmarkDao is required");

        this.itemDAO = itemDAO;
        this.bookmarkDao = bookmarkDao;
    }

    // on path /mylibrary/
    @RequestMapping(value = "/")
    public ModelAndView handleRequest(Principal principal) throws JSONException {

        String id = principal.getName();
        List<Bookmark> bookmarks = bookmarkDao.getByUsername(id);

        ModelAndView modelAndView = new ModelAndView("jsp/mylibrary");
        modelAndView.addObject("username", id);
        modelAndView.addObject("bookmarks", bookmarks);
        modelAndView.addObject("itemDAO", itemDAO);
        return modelAndView;
    }

    // on path /mylibrary/addbookmark
    @RequestMapping(value = "/addbookmark/", method = RequestMethod.POST)
    public String handleAddBookmarkRequest(HttpServletResponse response,
            @RequestParam("itemId") String itemId,
            @RequestParam("page") int page, Principal principal,
            @RequestParam("thumbnailURL") String thumbnailURL,
            @RequestParam(value = "redirect", required = false) boolean redirect) {

        Bookmark bookmark = new Bookmark(principal.getName(), itemId, page,
                thumbnailURL, new Date());
        String error = null;

        try {
            bookmarkDao.add(bookmark);
        } catch (TooManyBookmarksException e1) {
            error = e1.getMessage();
        }

        if (redirect) {
            return "redirect:/mylibrary/";
        }

        // Write JSON response.
        String json = "{\"bookmarkcreated\":true}";
        if (error!=null) {
            json = "{\"bookmarkcreated\":false, \"error\":\""+error+"\"}";
        }
        try {
            response.setContentType("application/json");
            response.getWriter().write(json);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;

    }

    // on path /mylibrary/deletebookmark
    @RequestMapping(value = "/deletebookmark/", method = RequestMethod.POST)
    public String handleDeleteBookmarkRequest(HttpServletResponse response,
            @RequestParam("itemId") String itemId,
            @RequestParam("page") int page, Principal principal,
            @RequestParam(value = "redirect", required = false) boolean redirect) {

        bookmarkDao.delete(principal.getName(), itemId, page);

        if (redirect) {
            return "redirect:/mylibrary/";
        } else {
            try {
                response.getWriter().write("{\"bookmarkdeleted\":true}");
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }

    }

}
