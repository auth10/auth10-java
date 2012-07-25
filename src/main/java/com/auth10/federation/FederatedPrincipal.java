//-----------------------------------------------------------------------
// <copyright file="FederatedPrincipal.java" company="Microsoft">
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

import java.security.Principal;
import java.util.Collections;
import java.util.List;

public class FederatedPrincipal implements Principal {
	private static final String NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
	private static final String EmailClaimType = "http://schemas.xmlsoap.org/claims/EmailAddress";
	
	protected List<Claim> claims = null;

	public FederatedPrincipal(List<Claim> claims) {
		this.claims = claims;
	}

	public String getName() {
		String name = "";
		
		for (Claim claim : claims) {
			if (claim.getClaimType().equals(NameClaimType))
				name = claim.getClaimValue();
		}
		
		if (name.isEmpty()){
			for (Claim claim : claims) {
				if (claim.getClaimType().equals(EmailClaimType))
					name = claim.getClaimValue();
			}			
		}
		
		return name;
	}

	public List<Claim> getClaims() {
		return Collections.unmodifiableList(this.claims);
	}
}
