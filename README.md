# Cordova-AES256 Encryption And Decryption

This _**cordova**_ _**ionic**_ plugin allows you to perform _**AES 256**_ encryption and decryption on the plain text. It's a cross-platform plugin which supports both Android and iOS. The encryption and decryption are performed on the device native layer so that the performance is much faster.

- [Getting Started](https://github.com/Ideas2IT/cordova-aes256/blob/master/README.md#getting-started)

# Getting Started

1. **Install plugin**  
 _`ionic cordova plugin add https://github.com/Ideas2IT/cordova-aes256`_
 
 
2. **Declare cordova variable and access the plugin after the platform get initialized**

```
import { Injectable } from '@angular/core';
import { Platform } from 'ionic-angular/index';
declare var cordova: any;

@Injectable()
export class AES256Provider {

  secureKey: String = '123456789101234567890123456789011'; // Any string, the length should be 32
  secureIV: String = '1234567891123456'; // Any string, the length should be 16

  constructor(private platform: Platform) {
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
      cordova.plugins.AES256.encrypt(secureKey, secureIV, encryptedData,
        (decryptedData) => {
          console.log('Decrypted Data----', decryptedData);
        }, (error) => {
          console.log('Error----', error);
        });
    });
  }

}
```
