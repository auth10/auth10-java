//-----------------------------------------------------------------------
// <copyright file="FederatedLoginManager.java" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//
// 
//    Copyright 2012 Microsoft Corporation
//    All rights reserved.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
// EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR 
// CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
//
// See the Apache Version 2.0 License for specific language governing 
// permissions and limitations under the License.
// </copyright>
//
// <summary>
//     
//
// </summary>
//----------------------------------------------------------------------------------------------

package com.auth10.federation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

public class FederatedLoginManager {
	private static final DateTimeFormatter CHECKING_FORMAT = ISODateTimeFormat.dateTime().withZone(DateTimeZone.UTC);
	
	private HttpServletRequest request;
	private FederatedAuthenticationListener listener;

	public static FederatedLoginManager fromRequest(HttpServletRequest request) {
		return fromRequest(request, null);
	}

	public static FederatedLoginManager fromRequest(HttpServletRequest request, FederatedAuthenticationListener listener) {
		return new FederatedLoginManager(request, listener);
	}

	protected FederatedLoginManager(HttpServletRequest request, FederatedAuthenticationListener listener) {
		this.request = request;
		this.listener = listener;
	}

	public final FederatedPrincipal authenticate(String token, HttpServletResponse response) throws FederationException {
		List<Claim> claims = null;

		try {
			SamlTokenValidator validator = new SamlTokenValidator();

			this.setTrustedIssuers(validator);
			
			this.setAudienceUris(validator);

			this.setThumbprint(validator);			

			claims = validator.validate(token);

			FederatedPrincipal principal = new FederatedPrincipal(claims);
			
			if (listener != null) listener.OnAuthenticationSucceed(principal);
			
			return principal;			
		} catch (FederationException e) {
			throw e;
		} catch (Exception e) {
			throw new FederationException("Federated Login failed!", e);
		} finally {
			if (claims == null) {
				request.getSession().invalidate();
				throw new FederationException("Invalid Token");
			}
		}
	}
		
	protected void setTrustedIssuers(SamlTokenValidator validator) 
			throws FederationException {
		String[] trustedIssuers = FederatedConfiguration.getInstance().getTrustedIssuers();
		if (trustedIssuers != null) {
			validator.getTrustedIssuers().addAll(Arrays.asList(trustedIssuers));
		}		
	}
	
	protected void setAudienceUris(SamlTokenValidator validator) 
			throws FederationException {
		String[] audienceUris = FederatedConfiguration.getInstance().getAudienceUris();
		for (String audienceUriStr : audienceUris) {
			try {
				validator.getAudienceUris().add(new URI(audienceUriStr));
			} catch (URISyntaxException e) {
				throw new FederationException("Federated Login Configuration failure: Invalid Audience URI", e);
			}
		}
	}
	
	protected void setThumbprint(SamlTokenValidator validator)
			throws FederationException {
		String thumbprint = FederatedConfiguration.getInstance().getThumbprint();
		validator.setThumbprint(thumbprint);
	}

	public static String getFederatedLoginUrl(String returnURL) {
		return getFederatedLoginUrl(null, null, returnURL); 
	}
	
	public static String getFederatedLoginUrl(String realm, String replyURL, String returnURL) {
		Calendar c = Calendar.getInstance();

		String encodedDate = CHECKING_FORMAT.print(c.getTimeInMillis());

		if (realm == null) {
			realm = FederatedConfiguration.getInstance().getRealm();
		}
		String encodedRealm = URLUTF8Encoder.encode(realm);

		String encodedReply = null;
		if (replyURL != null) {			
			encodedReply = URLUTF8Encoder.encode(replyURL);
		}
		else {
			encodedReply = (FederatedConfiguration.getInstance().getReply() != null) ? URLUTF8Encoder.encode(FederatedConfiguration.getInstance().getReply()) : null;
		}

		String encodedRequest = (returnURL != null) ? URLUTF8Encoder.encode(returnURL) : "";

		String federatedLoginURL = FederatedConfiguration.getInstance()
				.getStsUrl()
				+ "?wa=wsignin1.0&wtrealm="	+ encodedRealm
				+ "&wctx=" + encodedRequest
				+ "&id=passive"
				+ "&wct=" + encodedDate;

		if (encodedReply != null) {
			federatedLoginURL += "&wreply=" + encodedReply;
		}

		return federatedLoginURL;
	}
}
