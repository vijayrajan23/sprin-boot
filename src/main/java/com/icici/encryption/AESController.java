package com.icici.encryption;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import com.icici.encryption.EncryptionApplication;

@RestController
@RequestMapping("/iciciencryption")

public class AESController {

	
	@Autowired
	private EncryptionApplication encryptionapp;
	@Autowired
	AES aesapp;
    @GetMapping("/apitesting")
	public String AESEncrption() {
		String iciciresponsedata = aesapp.createProducts();
        return iciciresponsedata;
    }

	
}
