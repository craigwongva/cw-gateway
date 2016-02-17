package gateway.auth.rest.dto;

public final class RestCredentials {

    private String requestData;
    private String signature;

    public RestCredentials(String requestData, String signature) {
	this.requestData = requestData;
	this.signature = signature;
    }

    public String getRequestData() {
	return requestData;
    }

    public String getSignature() {
	return signature;
    }

}