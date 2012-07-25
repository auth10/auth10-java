This library speaks the WS-Federation protocol and SAML 1.1 and 2.0 tokens. It interops fine with Microsoft-related products like ADFS, Windows Azure Active Directory and Windows Identity Foundation.

The code is a simplified version with some improvements of the library released by Microsoft <https://github.com/WindowsAzure/azure-sdk-for-java-samples>. 

## Usage

 Clone it

	git clone https://github.com/auth10/auth10-java.git

Or download it as zip from <https://github.com/auth10/auth10-java/zipball/master>

Import the Maven that was just downloaded in your project (File -> Import -> Existing Maven Projects)

Add a reference to `com.auth10.federation` library from your project. Edit your project Maven file `pom.xml` and add this:

```xml
<dependency>
	<groupId>com.auth10.federation</groupId>
	<artifactId>auth10-federation</artifactId>
	<version>0.0.1-SNAPSHOT</version>
</dependency>
```

Add a federation.properties file under `resources` folder:

```
federation.trustedissuers.issuer=https://your_identity_provider/
federation.trustedissuers.thumbprint=CF50166CE4B....signing cert thumbprint...4DA668F96BF
federation.trustedissuers.friendlyname=My Identity Provider
federation.audienceuris=http://localhost:8080/sample-federation/
federation.realm=http://localhost:8080/sample-federation/
federation.enableManualRedirect=false
```

Add the `WSFederationFilter` to the `web.xml` file:

```xml
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
```


