package gateway.auth.rest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class AuthenticationRequestWrapper extends HttpServletRequestWrapper {

    private final String payload;

    public AuthenticationRequestWrapper(HttpServletRequest req) {
	super(req);

	payload = req.getParameter("body");
    }

    public String getPayload() {
	return payload;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
	final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(payload.getBytes());
	ServletInputStream inputStream = new ServletInputStream() {
	    public int read() throws IOException {
		return byteArrayInputStream.read();
	    }

	    @Override
	    public boolean isFinished() {
		// TODO Auto-generated method stub
		return false;
	    }

	    @Override
	    public boolean isReady() {
		// TODO Auto-generated method stub
		return false;
	    }

	    @Override
	    public void setReadListener(ReadListener arg0) {
		// TODO Auto-generated method stub

	    }
	};
	return inputStream;
    }
}
