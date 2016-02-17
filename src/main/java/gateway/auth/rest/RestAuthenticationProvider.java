package gateway.auth.rest;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import gateway.auth.rest.dto.RestCredentials;
import gateway.auth.rest.dto.RestToken;

@Component
public class RestAuthenticationProvider implements AuthenticationProvider {

    // @Autowired
    // private UserService service;

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	RestToken restToken = (RestToken) authentication;

	String apiKey = restToken.getPrincipal();
	RestCredentials credentials = restToken.getCredentials();

	if (apiKey == null || credentials.getSignature() == null) {
	    throw new BadCredentialsException("Missing username or password.");
	}

	// get secret access key from api key
	String secret = "mysecret"; // service.loadSecretByUsername(apiKey);

	// if that username does not exist, throw exception
	// if (secret == null) {
	// throw new BadCredentialsException("Invalid username or password.");
	// }

	// calculate the hmac of content with secret key
	String hmac = calculateHMAC(secret, credentials.getRequestData());

	System.out.println("RequestData: " + credentials.getRequestData());
	System.out.println("Signature: " + credentials.getSignature());
	System.out.println("Calculated Signature: " + hmac);

	// check if signatures match
	if (!credentials.getSignature().equals(hmac)) {
	    throw new BadCredentialsException("Signature does not match!");
	}

	// this constructor create a new fully authenticated token, with the
	// "authenticated" flag set to true
	// we use null as to indicates that the user has no authorities. you can
	// change it if you need to set some roles.
	restToken = new RestToken(apiKey, credentials, restToken.getTimestamp(), null);

	return restToken;
    }

    public boolean supports(Class<?> authentication) {
	return RestToken.class.equals(authentication);
    }

    private String calculateHMAC(String secret, String data) {
	try {
	    Mac mac = Mac.getInstance("HmacSHA256");
	    mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
	    return new String(Base64.encodeBase64(mac.doFinal(data.getBytes())));
	} catch (GeneralSecurityException e) {
	    throw new IllegalArgumentException();
	}
    }
}