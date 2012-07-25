//-----------------------------------------------------------------------
// <copyright file="ClaimTest.java" company="Microsoft">
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

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import com.auth10.federation.Claim;

import junit.framework.TestCase;

public class ClaimTest extends TestCase {

	public void testClaimShouldSerialize() throws Exception {
		OutputStream outputStreamStub = new OutputStream() {
			public void write(int b) throws IOException {
				// Do nothing
			}
		};
		
		ObjectOutputStream objectStream = new ObjectOutputStream(outputStreamStub);

		Claim claim = new Claim("http://mysite/myclaim", "claimValue");

		// Verify that the object can be serialized
		objectStream.writeObject(claim);
	}
}
