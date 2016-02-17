package gateway.auth.rest;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

import gateway.auth.rest.dto.RestCredentials;
import gateway.auth.rest.dto.RestToken;

public class RestSecurityFilter extends GenericFilterBean {

    // Enable Multi-Read for PUT and POST requests
    private static final Set<String> METHOD_HAS_CONTENT = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER) {
        private static final long serialVersionUID = 1L; 
        { add("PUT"); add("POST"); }
    };
    
    private AuthenticationManager authenticationManager;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private Md5PasswordEncoder md5;    

    public RestSecurityFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, new RestAuthenticationEntryPoint());
        ((RestAuthenticationEntryPoint)this.authenticationEntryPoint).setRealmName("Secure realm");
    }

    public RestSecurityFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.md5 = new Md5PasswordEncoder();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        // Use wrapper so that InputStream can be read multiple times down the filter chain
        AuthenticationRequestWrapper request = new AuthenticationRequestWrapper((HttpServletRequest)req);
        HttpServletResponse response = (HttpServletResponse)resp;
        printPrettyRequest(request); //DEBUG
        
        // Authorization header is in the form <public_access_key>:<signature>
        String credentials = request.getHeader("Authorization"), apiKey = null, signature = null;        
        if (credentials != null && credentials.contains(":")) {
            String auth[] = credentials.split(":");                        
            apiKey = auth[0];
            signature = auth[1];
        }
                          
        // Container for the data to sign, and the signature from signing the data.
        RestCredentials restCredential = new RestCredentials(buildRequestSignatureData(request), signature);

        try {    
            // Request the authentication manager to authenticate the token (throws exception)
            Authentication successfulAuthentication = 
        	    authenticationManager.authenticate(new RestToken(apiKey, restCredential, null));
            
            // Pass the successful token to the SecurityHolder where it can be
            // retrieved by this thread at any stage.
            SecurityContextHolder.getContext().setAuthentication(successfulAuthentication);
            
            // Continue with the Filters
            chain.doFilter(request, response);
        } catch (AuthenticationException authenticationException) {
            // If it fails clear this threads context and kick off the
            // authentication entry point process.
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, authenticationException);
        }
    }
    
    private String buildRequestSignatureData(AuthenticationRequestWrapper request) {       
        boolean hasContent = METHOD_HAS_CONTENT.contains(request.getMethod());
        String contentMd5 = hasContent ? md5.encodePassword(request.getPayload(), null) : "";
        String contentType = hasContent ? request.getContentType() : "";
        
        // Parse out boundary information for testing purposes.
        if( contentType.contains(";") ) {
            contentType = contentType.split(";")[0];
        }
        
        // Build content string to sign
        StringBuilder sig = new StringBuilder();
        sig.append(request.getMethod()).append("\n")
              .append(contentMd5).append("\n")
              .append(contentType).append("\n")
//              .append(requestDate).append("\n") // Date header is not coming through
              .append(request.getRequestURI());	
        
        return sig.toString();
    }
    
    private void printPrettyRequest(AuthenticationRequestWrapper request) {
        System.out.println("Request payload: " + request.getPayload());        
        Enumeration headers = request.getHeaderNames();
        while( headers.hasMoreElements() ) {
            String header = headers.nextElement().toString();
            System.out.println("Request Header: "+ header + ":"+ request.getHeader(header));
        }        
    }
}