This library speaks the WS-Federation protocol and SAML 1.1 and 2.0 tokens. It interops fine with Microsoft-related products like ADFS, Windows Azure Active Directory and Windows Identity Foundation.

## Usage

 Clone it

	git clone https://github.com/woloski/Auth10.Java.git

Or download it as zip

	https://github.com/woloski/Auth10.Java/zipball/master

Import the Maven project to your source code (File -> Import -> Existing Maven Projects)

Add a reference to `com.auth10.federation` library from your project. Using Maven, edit your `pom.xml` and add this:

	<dependency>
  		<groupId>com.auth10.federation</groupId>
  		<artifactId>waad-federation</artifactId>
  		<version>0.0.1-SNAPSHOT</version>
  	</dependency>
  	
Add a federation.properties file under `resources` folder:

	federation.trustedissuers.issuer=https://your_identity_provider/
	federation.trustedissuers.thumbprint=CF50166CE4B....signing cert thumbprint...4DA668F96BF
	federation.trustedissuers.friendlyname=My Identity Provider
	federation.audienceuris=http://localhost:8080/sample-federation/
	federation.realm=http://localhost:8080/sample-federation/
	federation.enableManualRedirect=false

Add the `WSFederationFilter` to the `web.xml` file:

	<filter>
	  <filter-name>FederationFilter</filter-name>
	  <filter-class>com.auth10.federation.WSFederationFilter</filter-class>
	  <init-param>
	    <param-name>login-page-url</param-name>
	    <!-- this is used only if manual redirect is enabled. Otherwise the user will be automatically redirected to the identity provider when browsing the website -->
	    <param-value>login.jsp</param-value>
	  </init-param>
	  <init-param>
	    <param-name>exclude-urls-regex</param-name>
	    <!-- e.g.: public folder won't be affected by the filter. To add more concat with pipe (|) -->
	    <param-value>/public/*</param-value>
	  </init-param>
	</filter>
	<filter-mapping>
	  <filter-name>FederationFilter</filter-name>
	  <url-pattern>/*</url-pattern>
	</filter-mapping>






