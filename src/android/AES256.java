package com.ideas2it.aes256;

import android.util.Base64;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;


import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class used to perform AES encryption and decryption.
 */
public class AES256 extends CordovaPlugin {

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        try {
            String secureKey = args.getString(0);
            String iv = args.getString(1);
            String value = args.getString(2);
            if (ENCRYPT.equalsIgnoreCase(action)) {
                callbackContext.success(encrypt(secureKey, value, iv));
                return true;
            } else if (DECRYPT.equalsIgnoreCase(action)) {
                callbackContext.success(decrypt(secureKey, value, iv));
                return true;
            } else {
                callbackContext.error("Invalid method call");
                return false; 
            }
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
        }
        return false;
    }

    private String encrypt(String secureKey, String value, String iv) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(digest.digest(secureKey.getBytes("UTF-8")), "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);

    }

    private String decrypt(String secureKey, String value, String iv) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(digest.digest(secureKey.getBytes("UTF-8")), "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] original = cipher.doFinal(Base64.decode(value, Base64.DEFAULT));

        return new String(original);
    }
}
