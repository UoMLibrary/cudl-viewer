package ulcambridge.foundations.viewer.authentication;

import java.io.IOException;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import ulcambridge.foundations.viewer.dao.BookmarkDao;
import ulcambridge.foundations.viewer.exceptions.TooManyBookmarksException;
import ulcambridge.foundations.viewer.model.Bookmark;

@Controller
public class LoginController {

	protected final Log logger = LogFactory.getLog(getClass());
	private final OAuth2RestOperations googleTemplate;
	private final OAuth2RestOperations facebookTemplate;
	private UsersDao usersDao;
	private BookmarkDao bookmarkDao;

	@Autowired
	public LoginController(OAuth2RestOperations googleTemplate, OAuth2RestOperations facebookTemplate) {
		this.googleTemplate = googleTemplate;
		this.facebookTemplate = facebookTemplate;
	}

	@Autowired
	public void setUsersDao(UsersDao usersDao) {
		this.usersDao = usersDao;
	}
	
	@Autowired
	public void setBookmarkDao(BookmarkDao bookmarkDao) {
		this.bookmarkDao = bookmarkDao;
	}	

	// on path /auth/login/
	@RequestMapping(value = "/login")
	public ModelAndView handleLoginRequest(
			@RequestParam(value = "error", required = false) String error,
			ModelMap model) {

		ModelAndView modelAndView = new ModelAndView("jsp/login");
		model.put("error", error);
		return modelAndView;
	}

	/**
	 * Handles and retrieves the denied JSP page. This is shown whenever a
	 * regular user tries to access an admin only page.
	 * 
	 * @return the name of the JSP page
	 */
	// on path /auth/denied/
	@RequestMapping(value = "/denied", method = RequestMethod.GET)
	public String getDeniedPage() {

		return "jsp/accessdenied";
	}

	// Login using Google oauth.  Note this is also return uri.
	// on path /auth/oauth2/google 
	@RequestMapping(value = "/oauth2/google")
	public ModelAndView handleGoogleRequest(HttpSession session, HttpServletResponse response)
			throws JSONException, IOException, NoSuchAlgorithmException {
			
		// Make Google profile request 
		String result = googleTemplate
				.getForObject(
						URI.create("https://www.googleapis.com/plus/v1/people/me/openIdConnect"),
						String.class);
		// https://www.googleapis.com/oauth2/v1/userinfo?alt=json			
		
		JSONObject json = new JSONObject(result);
		String id = json.getString("sub");
		String email = json.getString("email");
		String email_verified = json.getString("email_verified");
				
		// Record email address if present and verified.
		String emailEncoded = null;
		if (email_verified !=null && email!=null && email_verified.equals("true")) {
			emailEncoded = encode(email);
		}
		
		String usernameEncoded = "google:"+encode(id);
		
		// setup user in Spring Security and DB
		setupUser(usernameEncoded, emailEncoded, session);

		// This should only be called up until Jan 2017. 
		migrateGoogleUser(usernameEncoded);		
		
		// forward to /mylibrary/
		response.sendRedirect("/mylibrary/");

		return null;
	}
	
	// Login using Facebook oauth.  Note this is also return uri.
	// on path /auth/oauth2/facebook
	@RequestMapping(value = "/oauth2/facebook")
	public ModelAndView handleFacebookRequest(HttpSession session, HttpServletResponse response)
			throws JSONException, IOException, NoSuchAlgorithmException {
			
		// Make Google profile request 
		String result = facebookTemplate
				.getForObject(
						URI.create("https://graph.facebook.com/me/"),
						String.class);
		
		JSONObject json = new JSONObject(result);
		String id = json.getString("id");
		String email = json.getString("email");
				
		// Record email address if present and verified.
		String emailEncoded = null;
		if (email!=null) {
			emailEncoded = encode(email);
		}
		
		String usernameEncoded = "facebook:"+encode(id);
		
		// setup user in Spring Security and DB
		setupUser(usernameEncoded, emailEncoded, session);

		// forward to /mylibrary/
		response.sendRedirect("/mylibrary/");

		return null;
	}	
	
	/**
	 * Encode (SHA-256) specified input and convert to hex. 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String encode(String input) throws NoSuchAlgorithmException  {
		
		// generate hash
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(input.getBytes());
		byte bytes[] = messageDigest.digest();
		
		// convert to hex
		StringBuffer hash = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			hash.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}
		return new String(hash);
		
	}
	
	/**
	 * Creates the user in Spring Security and in the database if needed and
	 * puts the userDetails in the session. 
	 * 
	 * @param id
	 * @param session
	 */
	private void setupUser(String username, String email, HttpSession session) {
		
		// Create user in database if required, and store details in user session.
		User user = usersDao.createUser(username, email);
		session.setAttribute("user", user);

		// Create user in Spring security
		Authentication auth = new PreAuthenticatedAuthenticationToken(username, null,
				AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils.join(user.getUserRoles(), ",")));
		SecurityContextHolder.getContext().setAuthentication(auth);
	}
	
	
	/**
	 * Gets the old google id for this user and moves any bookmarks over to the new
	 * username.  Note this will stop working Jan 2017 when google stops proving the 
	 * openid_id. 
	 *  
	 * @param username
	 * @throws JSONException
	 */
	private void migrateGoogleUser(String username) throws JSONException {
		
		// Does this user have an old OpenID 2.0 id?
		String openid_id = null;
		Map<String, Object> map = googleTemplate.getAccessToken().getAdditionalInformation();
		if (map.containsKey("id_token")) {
			Object idTokenEncoded = map.get("id_token");
			Jwt id_token = JwtHelper.decode(idTokenEncoded.toString());
			JSONObject json = new JSONObject(id_token.getClaims());
			
			if (json.has("openid_id")) {
			  openid_id = json.get("openid_id").toString();
			}
		}
		if (openid_id==null) { return;	}
		
		// Does this old user id have any bookmarks?
		List<Bookmark> oldBookmarks = bookmarkDao.getByUsername(openid_id);
		for (int i=0; i<oldBookmarks.size(); i++) {
			Bookmark bookmark = oldBookmarks.get(i);
			
			// change old bookmark to new username
			bookmark.setUsername(username);
			
			// add bookmark back to database with new username
			// and delete from DB using the old username.
			try {
				bookmarkDao.add(bookmark);
				bookmarkDao.delete(openid_id, bookmark.getItemId(), bookmark.getPage());
				
			} catch (TooManyBookmarksException e) {
				// this should not occur
				e.printStackTrace();
			}			
			
		}
	
	}
}