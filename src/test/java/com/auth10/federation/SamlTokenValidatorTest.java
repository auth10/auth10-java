//-----------------------------------------------------------------------
// <copyright file="SamlTokenValidatorTest.java" company="Microsoft">
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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.xml.sax.SAXException;

import com.auth10.federation.Claim;
import com.auth10.federation.FederationException;
import com.auth10.federation.SamlTokenValidator;

import junit.framework.TestCase;

public class SamlTokenValidatorTest extends TestCase {

	private String office365Token = "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"><t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2012-03-02T19:09:43.623Z</wsu:Created><wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2012-03-03T07:09:43.623Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><EndpointReference xmlns=\"http://www.w3.org/2005/08/addressing\"><Address>spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><Assertion ID=\"_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6\" IssueInstant=\"2012-03-02T19:09:44.201Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"><Issuer>00000001-0000-0000-c000-000000000000@014310f7-b77f-44f7-8e06-2943a117ea20</Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><ds:Reference URI=\"#_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><ds:DigestValue>l4AXtBPH14btldq0EugTdnlHc8k/O110bM2CC8y8CiU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Ede7Y1YKa4lZW4WklthtaZNO4f5CxXSJkiTpmSCyiqgOeKi6BwbSucA9+UdyTkNBy2Sa9Z3EizyxRXdgJbZzO0wD6lhxFyJe3I8WHojcM6zqyzjftTEfyNR/zT7LmRaSK8OtB5UKjlxyxiq8m6pjuW/RlUVPXeVVftzNQPwJKCCfcoGIevYZRNy8n3bUw8OyIsv7ZKpNxbkZ5vimHkkuaphg2QIo2gchjkM9+yJI9uVlSfLT0wgIG5SVN+L9kPLZNubioakX9/QPStb5bcYxZs7yxuQYO/BHWjD5p1uqDC+W3iwRfUswLvSRHFvbTu0kpQbo7mNtMuoDDwMtDY49mw==</ds:SignatureValue><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQER0D5COOC6hEo98EuuBOxDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTExMTIyMDgwMDAwWhcNMTMxMTIyMDgwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmlC+gdzz7teOfwZYMEk96lI6S00O6ITdu193iKwTjHHyGu2VKMHdb6xdszjVhOICFkvMhwMDQ2MBuCb8wU2jJi8Y8PlSX4Sfx7vVP9BaHmUn6ckxeiQqnyad7lhJYOZuZrQ9IsPifRbJAk0n5hXt6jVd6oZdvwJGT8TZyZFrDekASJHw+3VFEHzVQ3M9+ymzoDaZHCmGjFhHuKvnxV66C0Q6amR4R1ge/yy4/1b0PO8CwxrR5AF1QtZOR9kwilak3pKpF8vP6KCIMEbtjn4vHXoygjKJf4K7pGT2NXhQxX4fO1OHZsES25frhtTT84W2lEKnCsuHnRIu4M7TVuG4gQIDAQABo2IwYDBeBgNVHQEEVzBVgBCyJHFhOzG6/98kT1GOEHUuoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQER0D5COOC6hEo98EuuBOxDAJBgUrDgMCHQUAA4IBAQBLO2clVWCfXETw3g2EHAymfj6nNSy+O8zob6yb9WvhrCUzYLHcRXxjf0ZmuXN10uijEzmcuYnB2mTImU1dzihhBD8B10ZdIgRNgiYld8mWvmHHeWtaaPZuV15blXpXQ9mCIedup99XhiNvX/X2RuqlCSPv0qJxLM/S1Al7xVvRZSox8hTFlkdn3nhUKGYO9ggl7gVdSgONiTakC1Yy7yfw2KUcV+rVw16d/Hln1cgTTOk968DKQ/7rTHQMdjm2eAsXVHeRCPN5EiqXklkXP+GQOX2nvsD5nIF8V4C6L/isN1q4SWt294QDoJNLAfStt9orWjGfkz1U3CroOCg/dtw3</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>10037FFE817C9DFD@MicrosoftOnline.com</NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" /></Subject><Conditions NotBefore=\"2012-03-02T19:09:43.623Z\" NotOnOrAfter=\"2012-03-03T07:09:43.623Z\"><AudienceRestriction><Audience>spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=\"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/domain\"><AttributeValue>globalbank.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/CID\"><AttributeValue>bce06d92161d3513</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/Child\"><AttributeValue>FALSE</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/EmailAddress\"><AttributeValue>admin@globalbank.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/FirstName\"><AttributeValue>Matias</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/LastName\"><AttributeValue>Woloski</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/Managed\"><AttributeValue>TRUE</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/PUID\"><AttributeValue>10037FFE817C9DFD</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/TOUAccepted\"><AttributeValue>FALSE</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider\"><AttributeValue>00000001-0000-0000-c000-000000000000@014310f7-b77f-44f7-8e06-2943a117ea20</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=\"2012-03-02T14:15:37.000Z\"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></t:RequestedSecurityToken><t:RequestedAttachedReference><SecurityTokenReference d3p1:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\" xmlns:d3p1=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6</KeyIdentifier></SecurityTokenReference></t:RequestedAttachedReference><t:RequestedUnattachedReference><SecurityTokenReference d3p1:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\" xmlns:d3p1=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6</KeyIdentifier></SecurityTokenReference></t:RequestedUnattachedReference><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
	private String office365TokenInvalidSignature = "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"><t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2012-03-02T19:09:43.623Z</wsu:Created><wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2012-03-03T07:09:43.623Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><EndpointReference xmlns=\"http://www.w3.org/2005/08/addressing\"><Address>spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><Assertion ID=\"_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6\" IssueInstant=\"2012-03-02T19:09:44.201Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"><Issuer>00000001-0000-0000-c000-000000000000@014310f7-b77f-44f7-8e06-2943a117ea20</Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><ds:Reference URI=\"#_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><ds:DigestValue>l4AXtBPH14btldq0EugTdnlHc8k/O110bM2CC8y8CiU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Ade7Y1YKa4lZW4WklthtaZNO4f5CxXSJkiTpmSCyiqgOeKi6BwbSucA9+UdyTkNBy2Sa9Z3EizyxRXdgJbZzO0wD6lhxFyJe3I8WHojcM6zqyzjftTEfyNR/zT7LmRaSK8OtB5UKjlxyxiq8m6pjuW/RlUVPXeVVftzNQPwJKCCfcoGIevYZRNy8n3bUw8OyIsv7ZKpNxbkZ5vimHkkuaphg2QIo2gchjkM9+yJI9uVlSfLT0wgIG5SVN+L9kPLZNubioakX9/QPStb5bcYxZs7yxuQYO/BHWjD5p1uqDC+W3iwRfUswLvSRHFvbTu0kpQbo7mNtMuoDDwMtDY49mw==</ds:SignatureValue><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQER0D5COOC6hEo98EuuBOxDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTExMTIyMDgwMDAwWhcNMTMxMTIyMDgwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmlC+gdzz7teOfwZYMEk96lI6S00O6ITdu193iKwTjHHyGu2VKMHdb6xdszjVhOICFkvMhwMDQ2MBuCb8wU2jJi8Y8PlSX4Sfx7vVP9BaHmUn6ckxeiQqnyad7lhJYOZuZrQ9IsPifRbJAk0n5hXt6jVd6oZdvwJGT8TZyZFrDekASJHw+3VFEHzVQ3M9+ymzoDaZHCmGjFhHuKvnxV66C0Q6amR4R1ge/yy4/1b0PO8CwxrR5AF1QtZOR9kwilak3pKpF8vP6KCIMEbtjn4vHXoygjKJf4K7pGT2NXhQxX4fO1OHZsES25frhtTT84W2lEKnCsuHnRIu4M7TVuG4gQIDAQABo2IwYDBeBgNVHQEEVzBVgBCyJHFhOzG6/98kT1GOEHUuoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQER0D5COOC6hEo98EuuBOxDAJBgUrDgMCHQUAA4IBAQBLO2clVWCfXETw3g2EHAymfj6nNSy+O8zob6yb9WvhrCUzYLHcRXxjf0ZmuXN10uijEzmcuYnB2mTImU1dzihhBD8B10ZdIgRNgiYld8mWvmHHeWtaaPZuV15blXpXQ9mCIedup99XhiNvX/X2RuqlCSPv0qJxLM/S1Al7xVvRZSox8hTFlkdn3nhUKGYO9ggl7gVdSgONiTakC1Yy7yfw2KUcV+rVw16d/Hln1cgTTOk968DKQ/7rTHQMdjm2eAsXVHeRCPN5EiqXklkXP+GQOX2nvsD5nIF8V4C6L/isN1q4SWt294QDoJNLAfStt9orWjGfkz1U3CroOCg/dtw3</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>10037FFE817C9DFD@MicrosoftOnline.com</NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" /></Subject><Conditions NotBefore=\"2012-03-02T19:09:43.623Z\" NotOnOrAfter=\"2012-03-03T07:09:43.623Z\"><AudienceRestriction><Audience>spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=\"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/domain\"><AttributeValue>globalbank.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/CID\"><AttributeValue>bce06d92161d3513</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/Child\"><AttributeValue>FALSE</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/EmailAddress\"><AttributeValue>admin@globalbank.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/FirstName\"><AttributeValue>Matias</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/LastName\"><AttributeValue>Woloski</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/Managed\"><AttributeValue>TRUE</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/PUID\"><AttributeValue>10037FFE817C9DFD</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/claims/TOUAccepted\"><AttributeValue>FALSE</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider\"><AttributeValue>00000001-0000-0000-c000-000000000000@014310f7-b77f-44f7-8e06-2943a117ea20</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=\"2012-03-02T14:15:37.000Z\"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></t:RequestedSecurityToken><t:RequestedAttachedReference><SecurityTokenReference d3p1:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\" xmlns:d3p1=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6</KeyIdentifier></SecurityTokenReference></t:RequestedAttachedReference><t:RequestedUnattachedReference><SecurityTokenReference d3p1:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\" xmlns:d3p1=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_b9d6e49b-b16e-4c9a-8c38-cf3f4d06afb6</KeyIdentifier></SecurityTokenReference></t:RequestedUnattachedReference><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";

	public SamlTokenValidatorTest(String name) {
		super(name);
	}

	public void testOrgIdCertificateShouldBeValid() throws Exception {
		SamlTokenValidator validator = new SamlTokenValidator();

		validator.setThumbprint("3F5DFCDF4B3D0EAB9BA49BEFB3CFD760DA9CCCF1");
		validator.getAudienceUris()
				 .add(new URI("spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20"));

		validator.setValidateExpiration(false);

		List<Claim> claims = validator.validate(office365Token);

		assertEquals(10, claims.size());
	}

	public void testShouldValidateSaml11TokenWithRSTRAndReturnClaims()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		
		String validTestToken = "<trust:RequestSecurityTokenResponseCollection xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><trust:RequestSecurityTokenResponse Context=\"rm=0&amp;id=passive\"><trust:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2010-12-09T19:28:38.440Z</wsu:Created><wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2010-12-09T20:28:38.440Z</wsu:Expires></trust:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><EndpointReference xmlns=\"http://www.w3.org/2005/08/addressing\"><Address>https://localhost/javafederationtest/</Address></EndpointReference></wsp:AppliesTo><trust:RequestedSecurityToken><saml:Assertion MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"_86fa42ed-6ee5-43b9-a8cf-ee3a8147229c\" Issuer=\"SelfSTS\" IssueInstant=\"2010-12-09T19:28:38.440Z\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\"><saml:Conditions NotBefore=\"2010-12-09T19:28:38.440Z\" NotOnOrAfter=\"2010-12-09T20:28:38.440Z\"><saml:AudienceRestrictionCondition><saml:Audience>https://localhost/javafederationtest/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName=\"emailaddress\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>test@company.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"givenname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Joe</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"surname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Doe</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"otherphone\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>555-5555-5555</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"name\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>joe</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"Group\" AttributeNamespace=\"http://schemas.xmlsoap.org/claims\"><saml:AttributeValue>Sales</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><ds:Reference URI=\"#_86fa42ed-6ee5-43b9-a8cf-ee3a8147229c\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><ds:DigestValue>57glK3s7BXklywOUC0J0d3w5r9U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>JrzxId4c+Yic9aI66/cM3NOHXvSSLBiFLlWR8radGW6zBGojWiRHO1HEJB+UGxlpGpkZ58AT1EP3wWPNSmKyxV2L8lKujj0i4UmTxrTvbbUF5kRuR2umAnJT9PsyYR6vkxMO5hBkRjwOLn16pqvq3H5o8LYpTaQAS2BfS1jazmTdT22JJZwR6OL4RKNxTel0Wfd8c80SCodo3V1/K3lR0IT08wIKkG0Q/PEh7Hxe8cJr+koGwWAxXV0sM5+CPblCLnCND4BuF0yXXqxEPkMo/mH0vcS9nKXvHmWsEcKSrL9XU/hZODH62OJO18QnmKJubemlxNH9hfJuVZrk/rrlHA==</ds:SignatureValue><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIC3DCCAcSgAwIBAgIQbS3ivPN2R6hIR9HKG+N5jzANBgkqhkiG9w0BAQUFADASMRAwDgYDVQQDEwdTZWxmU1RTMB4XDTEwMDgxODEzMzMzOVoXDTExMDgxODE5MzMzOVowEjEQMA4GA1UEAxMHU2VsZlNUUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANm/pT0LHoWF3t98DCFPVZECg/6TapHnrlqc2WCQVrXvpcOYIqnfhK1dbx4bRFa+SPKzrMQEgxk6cxzIXQyefmnlECZ3o/N5mcDpvmsSekx5TOU/o1lJP05DwvNHMGijGnkHHjbGZOkXq6cJSHT30GQq3fx5aqzcdMwEUnVAwIGrl32Qhx8FQSFPg+tCODQpReB6GERfo6PHwyyHohT6oLOBUFWq4QHpcW2XTct6y7PZZKa+cYe593Clu9wYYCxWnkgHDIBmoVnlWPTHs2l2Xg7SqGlzQs5lmRYCOz5TUa4fshbugJQe4AqfynBSVUaoD2ITrgpQ79l8lzEPyhtlAJkCAwEAAaMuMCwwCwYDVR0PBAQDAgTwMB0GA1UdDgQWBBSEKxAcWCxnkPM/+ZuvZRJ7vy/QHjANBgkqhkiG9w0BAQUFAAOCAQEAUNKUX52mtBP+UMNj+8bY91YhOFONxIf1YXYE3kV+7BYSGpChebaVtRmW9rIgq3GFibj689FZI0rNJ46YstUESeqOJxmy7GwFF2P728NA+mlrlxqAqlN1IQi7n29mC1C2NmbVriIoNAkRN4ljCYKB/T0Ubt/IezlXAbuvJ78G1zJSfbVv6AdrxJXuwkVvJGJBkBDL8esbO6WS54r0qhgCOhAr46ccDm62dDRuaPFYrY5wC4gZ8I7mhkbh2xdt8IVVnNNAUS2TX4ue8JVyty6AwIGgtsweD1145VdK79XejXcgiRCs3zchgKJa7z8YrtTsD9yLXIGj2yB7XnXO6wNcmA==</X509Certificate></X509Data></KeyInfo></ds:Signature></saml:Assertion></trust:RequestedSecurityToken><trust:RequestedAttachedReference><o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><o:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">_86fa42ed-6ee5-43b9-a8cf-ee3a8147229c</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedAttachedReference><trust:RequestedUnattachedReference><o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><o:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">_86fa42ed-6ee5-43b9-a8cf-ee3a8147229c</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedUnattachedReference><trust:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</trust:TokenType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>";

		SamlTokenValidator validator = new SamlTokenValidator();

		validator.getTrustedIssuers().add("CN=SelfSTS");
		validator.getAudienceUris().add(new URI("https://localhost/javafederationtest/"));
		validator.setValidateExpiration(false);

		List<Claim> claims = null;
		claims = validator.validate(validTestToken);

		assertEquals(6, claims.size());
		assertEquals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", ((Claim) claims.get(0)).getClaimType());
		assertEquals("test@company.com", ((Claim) claims.get(0)).getClaimValue());
	}

	public void testShouldValidateSaml20TokenWithRSTRAndReturnClaims()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		
		SamlTokenValidator validator = new SamlTokenValidator();

		validator.setThumbprint("3F5DFCDF4B3D0EAB9BA49BEFB3CFD760DA9CCCF1");
		validator.getAudienceUris()
				 .add(new URI("spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20"));

		validator.setValidateExpiration(false);

		List<Claim> claims = validator.validate(office365Token);

		assertEquals(10, claims.size());
		assertEquals("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/domain",	((Claim) claims.get(0)).getClaimType());
		assertEquals("globalbank.onmicrosoft.com", ((Claim) claims.get(0)).getClaimValue());
	}

	public void testShouldThrowForTamperedSignature()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		SamlTokenValidator validator = new SamlTokenValidator();

		try {
			validator.validate(office365TokenInvalidSignature);
			fail("The signature was tampered this should not validate");
		} catch (FederationException e) {
			// expected
			assertEquals("Invalid signature", e.getMessage());
		}
	}

	public void testShouldThrowBecauseTheTokenWasIssuedByUntrustedIssuer()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		SamlTokenValidator validator = new SamlTokenValidator();
		// don't configure trusted issuers.

		try {
			validator.validate(office365Token);
			fail("Trusted issuers were not set, throw");
		} catch (FederationException e) {
			// expected
			assertEquals("The token was issued by an authority that is not trusted", e.getMessage());
		}
	}

	public void testShouldThrowBecauseTheTokenAppliesToUnknownAudience()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		
		SamlTokenValidator validator = new SamlTokenValidator();

		String invalidTrustedIssuer = "3F5DFCDF4B3D0EAB9BA49BEFB3CFD760DA9EEEF1";
		validator.setThumbprint(invalidTrustedIssuer);

		try {
			validator.validate(office365Token);
			fail("AudienceUris was not set, throw");
		} catch (FederationException e) {
			// expected
		}
	}

	public void testShouldThrowBecauseTokenWasExpired()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		SamlTokenValidator validator = new SamlTokenValidator();

		validator.setThumbprint("3F5DFCDF4B3D0EAB9BA49BEFB3CFD760DA9CCCF1");
		validator.getAudienceUris()
				 .add(new URI("spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20"));

		try {
			validator.validate(office365Token);
			fail("Token expired should throw");
		} catch (FederationException e) {
			// expected
		}
	}

	public void testShouldValidateExpiredTokenWhenSettingValidateExpirationFalse()
			throws URISyntaxException, CertificateException, KeyException,
			ParserConfigurationException, SAXException, IOException,
			ConfigurationException, SecurityException, ValidationException,
			UnmarshallingException, FederationException,
			NoSuchAlgorithmException {
		SamlTokenValidator validator = new SamlTokenValidator();

		validator.setThumbprint("3F5DFCDF4B3D0EAB9BA49BEFB3CFD760DA9CCCF1");
		validator.getAudienceUris()
				 .add(new URI("spn:19b8831d-0827-432f-bfb6-e587e48c3ea9@014310f7-b77f-44f7-8e06-2943a117ea20"));

		validator.setValidateExpiration(false);
		validator.validate(office365Token);
	}
}
