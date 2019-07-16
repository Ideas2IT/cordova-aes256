# Cordova-AES256 Encryption And Decryption

This _**cordova**_ _**ionic**_ plugin allows you to perform _**AES 256**_ encryption and decryption on the plain text. It's a cross-platform plugin which supports both Android and iOS. The encryption and decryption are performed on the device native layer so that the performance is much faster. The entire operations is performed in the background thread.

### AES Encryption Mode
AES 256 CBC mode encryption is used. For Android, PKCS5Padding is used and for iOS PKCS7Padding is used.

- [Getting Started](https://github.com/Ideas2IT/cordova-aes256/blob/master/README.md#getting-started)
- [References](https://github.com/Ideas2IT/cordova-aes256/blob/master/README.md#references)

# Getting Started

1. **Install Plugins**  
 _`ionic cordova plugin add cordova-plugin-aes256-encryption`_
 
    _`cordova plugin add cordova-plugin-add-swift-support --save`_
 
2. **Declare cordova variable and access the plugin after the platform get initialized**

```
import { Injectable } from '@angular/core';
import { Platform } from 'ionic-angular/index';
declare var cordova: any;

@Injectable()
export class AES256Provider {

  secureKey: String = '12345678910123456789012345678901'; // Any string, the length should be 32
  secureIV: String = '1234567891123456'; // Any string, the length should be 16

  constructor(private platform: Platform) {
      // To generate random secure key
      this.generateSecureKey('some string');  // Optional
      
      // To generate random secure IV
      this.generateSecureIV('some string');   // Optional
      
      let data = "test";
      encrypt(this.secureKey, this.secureIV, data); 
      let encryptedData = "AE#3223==";
      decrypt(this.secureKey, this.secureIV, encryptedData);  
  }

  encrypt(secureKey, secureIV, data) {
    this.platform.ready().then(() => {
      cordova.plugins.AES256.encrypt(secureKey, secureIV, data,
        (encrypedData) => {
          console.log('Encrypted Data----', encrypedData);
        }, (error) => {
          console.log('Error----', error);
        });
    });
  }

  decrypt(secureKey, secureIV, encryptedData) {
    this.platform.ready().then(() => {
      cordova.plugins.AES256.decrypt(secureKey, secureIV, encryptedData,
        (decryptedData) => {
          console.log('Decrypted Data----', decryptedData);
        }, (error) => {
          console.log('Error----', error);
        });
    });
  }
  
  generateSecureKey(password) {
    this.platform.ready().then(() => {
      cordova.plugins.AES256.generateSecureKey(password,
        (secureKey) => {
          this.secureKey = secureKey;
          console.log('Secure Key----', secureKey);          
        }, (error) => {
          console.log('Error----', error);
        });
    });
  }
  
  generateSecureIV(password) {
    this.platform.ready().then(() => {
      cordova.plugins.AES256.generateSecureIV(password,
        (secureIV) => {
          this.secureIV = secureIV;
          console.log('Secure IV----', secureIV);          
        }, (error) => {
          console.log('Error----', error);
        });
    });
  }

}
```

# Installation Errors

```
Failed to install 'cordova-plugin-aes256-encryption': CordovaError: Version of installed plugin: "cordova-plugin-add-swift-support@1.7.1" does not satisfy dependency plugin requirement "cordova-plugin-add-swift-support@^2.0.1". Try --force to use installed plugin as dependency.

```

If Above error has occurred then run

```
ionic cordova plugin add cordova-plugin-aes256-encryption --force --save

```

# References
[https://developer.android.com/reference/javax/crypto/Cipher](https://developer.android.com/reference/javax/crypto/Cipher)

[https://github.com/SwiftyBeaver/AES256CBC](https://github.com/SwiftyBeaver/AES256CBC)

