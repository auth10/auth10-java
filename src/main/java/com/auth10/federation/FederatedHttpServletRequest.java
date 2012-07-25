package com.auth10.federation;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public final class FederatedHttpServletRequest extends HttpServletRequestWrapper  {

	 private final transient FederatedPrincipal principal;

	public FederatedHttpServletRequest(HttpServletRequest request, FederatedPrincipal principal) {
		super(request);
		this.principal = principal;
	}
	
	@Override
	public Principal getUserPrincipal() {
		return this.principal;
	}
	
	@Override
	public String getRemoteUser() {
		if (this.principal == null) {
			return super.getRemoteUser();
		} 
		else {
			return this.principal.getName();
		}
	}
}

