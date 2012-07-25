//-----------------------------------------------------------------------
// <copyright file="SamlTokenValidator.java" company="Microsoft">
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
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@SuppressWarnings("deprecation")
public class SamlTokenValidator {
	public static final int MAX_CLOCK_SKEW_IN_MINUTES = 3;
	private List<String> trustedIssuers;
	private List<URI> audienceUris;
	private boolean validateExpiration = true;
	private String thumbprint;

	public SamlTokenValidator() throws ConfigurationException {
		this(new ArrayList<String>(), new ArrayList<URI>());
	}

	public SamlTokenValidator(List<String> trustedIssuers,
			List<URI> audienceUris) throws ConfigurationException {
		super();
		this.trustedIssuers = trustedIssuers;
		this.audienceUris = audienceUris;
		DefaultBootstrap.bootstrap();
	}

	public List<String> getTrustedIssuers() {
		return this.trustedIssuers;
	}

	public void setTrustedIssuers(List<String> trustedIssuers) {
		this.trustedIssuers = trustedIssuers;
	}

	public List<URI> getAudienceUris() {
		return this.audienceUris;
	}

	public void setAudienceUris(List<URI> audienceUris) {
		this.audienceUris = audienceUris;
	}

	public boolean getValidateExpiration() {
		return validateExpiration;
	}

	public void setValidateExpiration(boolean value) {
		this.validateExpiration = value;
	}

	public List<Claim> validate(String envelopedToken)
			throws ParserConfigurationException, SAXException, IOException,
			FederationException, ConfigurationException, CertificateException,
			KeyException, SecurityException, ValidationException,
			UnmarshallingException, URISyntaxException,
			NoSuchAlgorithmException {
		
		SignableSAMLObject samlToken;
		
		if (envelopedToken.contains("RequestSecurityTokenResponse")) {
			samlToken = getSamlTokenFromRstr(envelopedToken);
		} else {
			samlToken = getSamlTokenFromSamlResponse(envelopedToken);
		}

		boolean valid = validateToken(samlToken);
		
		if (!valid) {
			throw new FederationException("Invalid signature");
		}

		boolean trusted = false;

		for (String issuer : this.trustedIssuers) {
			trusted |= validateIssuerUsingSubjectName(samlToken, issuer);
		}

		if (!trusted && (this.thumbprint != null)) {
			trusted = validateIssuerUsingCertificateThumbprint(samlToken,
					this.thumbprint);
		}

		if (!trusted) {
			throw new FederationException(
					"The token was issued by an authority that is not trusted");
		}

		String address = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			address = getAudienceUri((org.opensaml.saml1.core.Assertion) samlToken);
		}

		if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
			address = getAudienceUri((org.opensaml.saml2.core.Assertion) samlToken);
		}

		URI audience = new URI(address);

		boolean validAudience = false;
		for (URI audienceUri : audienceUris) {
			validAudience |= audience.equals(audienceUri);
		}

		if (!validAudience) {
			throw new FederationException(String.format("The token applies to an untrusted audience: %s", new Object[] { audience }));
		}

		List<Claim> claims = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			claims = getClaims((org.opensaml.saml1.core.Assertion) samlToken);
		}

		if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
			claims = getClaims((org.opensaml.saml2.core.Assertion) samlToken);
		}

		if (this.validateExpiration) {

			boolean expired = false;
			if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
				Instant notBefore = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotBefore().toInstant();
				Instant notOnOrAfter = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotOnOrAfter().toInstant();
				expired = validateExpiration(notBefore, notOnOrAfter);
			}

			if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
				Instant notBefore = ((org.opensaml.saml2.core.Assertion) samlToken).getConditions().getNotBefore().toInstant();
				Instant notOnOrAfter = ((org.opensaml.saml2.core.Assertion) samlToken).getConditions().getNotOnOrAfter().toInstant();
				expired = validateExpiration(notBefore, notOnOrAfter);
			}

			if (expired) {
				throw new FederationException("The token has been expired");
			}
		}

		return claims;
	}

	private static SignableSAMLObject getSamlTokenFromSamlResponse(
			String samlResponse) throws ParserConfigurationException,
			SAXException, IOException, UnmarshallingException {
		Document document = getDocument(samlResponse);

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement());
		org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) unmarshaller.unmarshall(document.getDocumentElement());
		SignableSAMLObject samlToken = (SignableSAMLObject) response.getAssertions().get(0);

		return samlToken;
	}

	private static SignableSAMLObject getSamlTokenFromRstr(String rstr)
			throws ParserConfigurationException, SAXException, IOException,
			UnmarshallingException, FederationException {
		Document document = getDocument(rstr);

		String xpath = "//*[local-name() = 'Assertion']";

		NodeList nodes = null;

		try {
			nodes = org.apache.xpath.XPathAPI.selectNodeList(document, xpath);
		} catch (TransformerException e) {
			e.printStackTrace();
		}

		if (nodes.getLength() == 0) {
			throw new FederationException("SAML token was not found");
		}

		Element samlTokenElement = (Element) nodes.item(0);
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlTokenElement);
		SignableSAMLObject samlToken = (SignableSAMLObject) unmarshaller.unmarshall(samlTokenElement);

		return samlToken;
	}

	private static String getAudienceUri(
			org.opensaml.saml2.core.Assertion samlAssertion) {
		org.opensaml.saml2.core.Audience audienceUri = samlAssertion.getConditions().getAudienceRestrictions().get(0)
				.getAudiences().get(0);
		return audienceUri.getAudienceURI();
	}

	private static String getAudienceUri(org.opensaml.saml1.core.Assertion samlAssertion) {
		
		org.opensaml.saml1.core.Audience audienceUri = samlAssertion.getConditions().getAudienceRestrictionConditions().get(0).getAudiences().get(0);
		return audienceUri.getUri();
	}

	private boolean validateExpiration(Instant notBefore, Instant notOnOrAfter) {
		
		Instant now = new Instant();
		Duration skew = new Duration(MAX_CLOCK_SKEW_IN_MINUTES * 60 * 1000);

		if (now.plus(skew).isBefore(notBefore)) {
			return true;
		}

		if (now.minus(skew).isAfter(notOnOrAfter)) {
			return true;
		}

		return false;
	}

	private static boolean validateToken(SignableSAMLObject samlToken)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		samlToken.validate(true);
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = (X509Certificate) KeyInfoHelper
				.getCertificates(keyInfo).get(0);

		BasicX509Credential cred = new BasicX509Credential();
		cred.setEntityCertificate(pubKey);
		cred.setEntityId("signing-entity-ID");

		ArrayList<Credential> trustedCredentials = new ArrayList<Credential>();
		trustedCredentials.add(cred);

		CollectionCredentialResolver credResolver = new CollectionCredentialResolver(
				trustedCredentials);

		KeyInfoCredentialResolver kiResolver = SecurityTestHelper
				.buildBasicInlineKeyInfoResolver();
		ExplicitKeySignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(
				credResolver, kiResolver);

		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new EntityIDCriteria("signing-entity-ID"));

		return engine.validate(signature, criteriaSet);
	}

	private static boolean validateIssuerUsingSubjectName(
			SignableSAMLObject samlToken, String subjectName)
			throws UnmarshallingException, ValidationException,
			CertificateException {
		
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);

		String issuer = pubKey.getSubjectDN().getName();
		return issuer.equals(subjectName);
	}

	private static boolean validateIssuerUsingCertificateThumbprint(
			SignableSAMLObject samlToken, String thumbprint)
			throws UnmarshallingException, ValidationException,
			CertificateException, NoSuchAlgorithmException {
		
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);

		String thumbprintFromToken = SamlTokenValidator
				.getThumbPrintFromCert(pubKey);

		return thumbprintFromToken.equalsIgnoreCase(thumbprint);
	}

	private static String getThumbPrintFromCert(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		return hexify(digest);
	}

	private static String hexify(byte bytes[]) {
		char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };

		StringBuffer buf = new StringBuffer(bytes.length * 2);

		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}

		return buf.toString();
	}

	private static List<Claim> getClaims(
			org.opensaml.saml2.core.Assertion samlAssertion)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		ArrayList<Claim> claims = new ArrayList<Claim>();

		List<org.opensaml.saml2.core.AttributeStatement> attributeStmts = samlAssertion
				.getAttributeStatements();

		for (org.opensaml.saml2.core.AttributeStatement attributeStmt : attributeStmts) {
			List<org.opensaml.saml2.core.Attribute> attributes = attributeStmt
					.getAttributes();

			for (org.opensaml.saml2.core.Attribute attribute : attributes) {
				String claimType = attribute.getName();
				String claimValue = getValueFrom(attribute.getAttributeValues());
				claims.add(new Claim(claimType, claimValue));
			}
		}

		return claims;
	}

	private static List<Claim> getClaims(
			org.opensaml.saml1.core.Assertion samlAssertion)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		ArrayList<Claim> claims = new ArrayList<Claim>();

		List<org.opensaml.saml1.core.AttributeStatement> attributeStmts = samlAssertion.getAttributeStatements();

		for (org.opensaml.saml1.core.AttributeStatement attributeStmt : attributeStmts) {
			List<org.opensaml.saml1.core.Attribute> attributes = attributeStmt.getAttributes();

			for (org.opensaml.saml1.core.Attribute attribute : attributes) {
				String claimType = attribute.getAttributeNamespace() + "/" + attribute.getAttributeName();
				String claimValue = getValueFrom(attribute.getAttributeValues());
				claims.add(new Claim(claimType, claimValue));
			}
		}

		return claims;
	}

	private static String getValueFrom(List<XMLObject> attributeValues) {
				
		StringBuffer buffer = new StringBuffer();
		
		for (XMLObject value : attributeValues) {
			if (buffer.length() > 0)
				buffer.append(',');
			buffer.append(value.getDOM().getTextContent());
		}

		return buffer.toString();
	}

	private static Document getDocument(String doc)
			throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder documentbuilder = factory.newDocumentBuilder();
		return documentbuilder.parse(new InputSource(new StringReader(doc)));
	}

	public void setThumbprint(String thumbprint) {
		this.thumbprint = thumbprint;
	}

	public String getThumbprint() {
		return thumbprint;
	}
}
