package com.icici.encryption;

public class Responses {
	

	String requestId;
	String service;
	String encryptedKey;
	String oaepHashingAlgorithm;
	String iv;
	String encryptedData;
	String clientInfo;
	String optionalParam;
	public String getRequestId() {
		return requestId;
	}
	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}
	public String getService() {
		return service;
	}
	public void setService(String service) {
		this.service = service;
	}
	public String getEncryptedKey() {
		return encryptedKey;
	}
	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}
	public String getOaepHashingAlgorithm() {
		return oaepHashingAlgorithm;
	}
	public void setOaepHashingAlgorithm(String oaepHashingAlgorithm) {
		this.oaepHashingAlgorithm = oaepHashingAlgorithm;
	}
	public String getIv() {
		return iv;
	}
	public void setIv(String iv) {
		this.iv = iv;
	}
	public String getEncryptedData() {
		return encryptedData;
	}
	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}
	public String getClientInfo() {
		return clientInfo;
	}
	public void setClientInfo(String clientInfo) {
		this.clientInfo = clientInfo;
	}
	public String getOptionalParam() {
		return optionalParam;
	}
	public void setOptionalParam(String optionalParam) {
		this.optionalParam = optionalParam;
	}
	@Override
	public String toString() {
		return "Responses [requestId=" + requestId + ", service=" + service + ", encryptedKey=" + encryptedKey
				+ ", oaepHashingAlgorithm=" + oaepHashingAlgorithm + ", iv=" + iv + ", encryptedData=" + encryptedData
				+ ", clientInfo=" + clientInfo + ", optionalParam=" + optionalParam + "]";
	}
	
	
	
	

}
