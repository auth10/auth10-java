//-----------------------------------------------------------------------
// <copyright file="Claim.java" company="Microsoft">
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

import java.io.Serializable;

public class Claim implements Serializable {

	private static final long serialVersionUID = -6595685426248469363L;
	private String claimType;
	private String claimValue;

	public Claim(String claimType, String claimValue) {
		super();
		this.claimType = claimType;
		this.claimValue = claimValue;
	}

	public String getClaimType() {
		return claimType;
	}

	public void setClaimType(String claimType) {
		this.claimType = claimType;
	}

	public String getClaimValue() {
		return claimValue;
	}

	public String[] getClaimValues() {
		return claimValue.split(",");
	}

	public void setClaimValue(String claimValue) {
		this.claimValue = claimValue;
	}

	@Override
	public String toString() {
		return "Claim [claimType=" + claimType + ", claimValue=" + claimValue + "]";
	}
}
