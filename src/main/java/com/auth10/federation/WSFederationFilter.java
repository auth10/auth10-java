package com.auth10.federation;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WSFederationFilter implements Filter {

	private static final String PRINCIPAL_SESSION_VARIABLE = "FederatedPrincipal";
	
	private String loginPage;
	private String excludedUrlsRegex;

	public void init(FilterConfig config) throws ServletException {
		this.loginPage = config.getInitParameter("login-page-url");
		this.excludedUrlsRegex = config.getInitParameter("exclude-urls-regex");
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		FederatedPrincipal principal = null;
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		// is the request is a token?
		if (this.isSignInResponse(httpRequest)) {				
			principal = this.authenticateWithToken(httpRequest, httpResponse);
			this.writeSessionToken(httpRequest, principal);
			this.redirectToOriginalUrl(httpRequest, httpResponse);
		}

		// is principal in session?
		if (principal == null && this.sessionTokenExists(httpRequest)) {				
			principal = this.authenticateWithSessionToken(httpRequest, httpResponse);
		}

		// if not authenticated at this point, redirect to login page 
		boolean excludedUrl = httpRequest.getRequestURL().toString().contains(this.loginPage) ||  
							 (this.excludedUrlsRegex != null && 
							 !this.excludedUrlsRegex.isEmpty() &&
							 Pattern.compile(this.excludedUrlsRegex).matcher(httpRequest.getRequestURL().toString()).find());
		
		if (!excludedUrl && principal == null) {
			if (!FederatedConfiguration.getInstance().getEnableManualRedirect()) {
				this.redirectToIdentityProvider(httpRequest, httpResponse);
			} else {
				this.redirectToLoginPage(httpRequest, httpResponse);
			}
			
			return;
		}
			
		chain.doFilter(new FederatedHttpServletRequest(httpRequest, principal), response);		
	}

	protected void redirectToLoginPage(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
		String encodedReturnUrl = URLUTF8Encoder.encode(getRequestPathAndQuery(httpRequest));	
		String redirect = this.loginPage + "?returnUrl=" + encodedReturnUrl;
		httpResponse.setHeader("Location", redirect);
		httpResponse.setStatus(302);
	}

	protected void redirectToIdentityProvider(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
		String wctx = getRequestPathAndQuery(httpRequest);
		String redirect = FederatedLoginManager.getFederatedLoginUrl(wctx);
		
		httpResponse.setHeader("Location", redirect);
		httpResponse.setStatus(302);
	}

	protected void redirectToOriginalUrl(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
		String wctx = httpRequest.getParameter("wctx");
		if (wctx != null) {
			httpResponse.setHeader("Location", wctx);
			httpResponse.setStatus(302);
		}
	}
	
	protected Boolean isSignInResponse(HttpServletRequest request) {
		if (request.getMethod().equals("POST") && 
			request.getParameter("wa").equals("wsignin1.0") && 
			request.getParameter("wresult") != null) {
			return true;
		}
		
		return false;
	}
	
	protected Boolean sessionTokenExists(HttpServletRequest request) {
		// this could use signed cookies instead of sessions
		return request.getSession().getAttribute(PRINCIPAL_SESSION_VARIABLE) != null;
	}
	
	protected FederatedPrincipal authenticateWithSessionToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return (FederatedPrincipal) request.getSession().getAttribute(PRINCIPAL_SESSION_VARIABLE);
	}
	
	protected void writeSessionToken(HttpServletRequest request, FederatedPrincipal principal) throws IOException {
		request.getSession().setAttribute(PRINCIPAL_SESSION_VARIABLE, principal);
	}
	
	protected FederatedPrincipal authenticateWithToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String token = request.getParameter("wresult").toString();
		
		if (token == null) {
			response.sendError(400, "You were supposed to send a wresult parameter with a token");
		}
		
		FederatedLoginManager loginManager = FederatedLoginManager.fromRequest(request, null);

		try {
			FederatedPrincipal principal = loginManager.authenticate(token, response);
			return principal;
		} catch (FederationException e) {
			response.sendError(500, "Oops and error occurred validating the token.");
		}
		
		return null;
	}

	public void destroy() {
	}
	
	private static String getRequestPathAndQuery(HttpServletRequest req) {
	    String reqUri = req.getRequestURI().toString();
	    String queryString = req.getQueryString(); 
	    if (queryString != null) {
	        reqUri += "?" + queryString;
	    }
	    
	    return reqUri;
	}
}
