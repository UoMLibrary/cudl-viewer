package ulcambridge.foundations.viewer.authentication;

import gs.spri.raven.RavenAuthenticationException;
import gs.spri.raven.RavenException;
import gs.spri.raven.RavenServlet;
import gs.spri.raven.RavenStateException;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class RavenLoginServlet extends RavenServlet {
	private static final long serialVersionUID = 6459642286645404697L;

	@Override
	protected void performAction(RavenServlet.Action a, HttpSession session,
			HttpServletResponse response) throws IOException, ServletException {
		// Store the username in the session and redirect to the raven login url
		session.setAttribute("cudl-raven-username", this.getUserName(session));

		// See LoginController
		response.sendRedirect("/auth/raven/login");

	}

	// Called when authentication is not possible because a user could not be
	// authenticated.
	protected void reportRavenAuthenticationException(
			RavenServlet.Action action,
			javax.servlet.http.HttpServletResponse res,
			RavenAuthenticationException cause) throws IOException {

		cause.printStackTrace();
		res.sendRedirect("/auth/login?error=There was a problem logging into Raven.");
	}

	// Called when authentication is not possible because of a protocol error.
	protected void reportRavenException(RavenServlet.Action action,
			javax.servlet.http.HttpServletResponse res, RavenException cause) throws IOException {

		cause.printStackTrace();
		res.sendRedirect("/auth/login?error=There was a problem logging into Raven.");
	}

	// Called when a token is received from Raven before the application has
	// requested one.
	protected void reportRavenStateException(RavenServlet.Action action,
			javax.servlet.http.HttpServletResponse res,
			RavenStateException cause) throws IOException {

		cause.printStackTrace();
		res.sendRedirect("/auth/login?error=There was a problem logging into Raven.");
	}

	// Called when a ServletException is thrown.
	protected void reportServletException(RavenServlet.Action action,
			javax.servlet.http.HttpServletResponse res,
			javax.servlet.ServletException cause) throws IOException {

		cause.printStackTrace();
		res.sendRedirect("/auth/login?error=There was a problem logging into Raven.");
	}

}