package gateway.auth.rest;

import java.security.GeneralSecurityException;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.utils.DateUtils;
import org.apache.http.entity.StringEntity;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;

public class Test {
    
//    public static void main(String args[]) {
////        HttpPut request = new HttpPut(path);
//	Md5PasswordEncoder md5 = new Md5PasswordEncoder();    
//	
//	    // content plain text
////	    String contentToEncode = md5.encodePassword("MyPayloadString", null);
////	    String contentType = "multipart/form-data; boundary=----WebKitFormBoundary0NN4A6HdmPREHyJJ";
////	    StringEntity data = new StringEntity(contentToEncode, contentType, HTTP.UTF_8);
//	    
////	    String date = DateUtils.formatDate(new Date());
//
//	    // create signature: method + content md5 + content-type + date + uri
//	    StringBuilder signature = new StringBuilder();
//	    signature
//	    	.append("POST").append("\n")
//	        .append(md5.encodePassword("MyPayloadString", null)).append("\n")
//	        .append("multipart/form-data").append("\n")
////	        .append(date).append("\n")
//	        .append("/job");
//
//	    System.out.println("Signature: " + signature);
//
////	    request.addHeader(new BasicHeader("Date", date));
//	    String auth = "rorf:" + Test.calculateHMAC("mysecret", signature.toString());
////	    request.addHeader(new BasicHeader("Authorization", auth));
//	    System.out.println(auth);
////
////	    // add data
////	    request.setEntity("MyPayloadString");
////	    
////	    // send request
////	    HttpClient client = new DefaultHttpClient();
////	    HttpResponse response = client.execute(request);
////	    
////	    int status = response.getStatusLine().getStatusCode();
////	    assert status == 200 : "Test failed";
//	}
    
    private static String calculateHMAC(String secret, String data) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal(data.getBytes());
            String result = new String(Base64.encodeBase64(rawHmac));
            return result;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException();
        }
    }
}
