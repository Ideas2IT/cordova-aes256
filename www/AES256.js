var exec = require('cordova/exec');

var AES256 = function () {};

AES256.prototype.encrypt = function (secureKey, iv, value, success, error) {
    if (secureKey && iv && value) {
        exec(success, error, 'AES256', 'encrypt', [secureKey, iv, value]);
    } else {
        success('');
    }
};

AES256.prototype.decrypt = function (secureKey, iv, value, success, error) {
    if (secureKey && iv && value) {
        exec(success, error, 'AES256', 'decrypt', [secureKey, iv, value]);
    } else {
        success('');
    }
};

AES256.prototype.generateSecureKey = function (password, success, error) {
    exec(success, error, 'AES256', 'generateSecureKey', [password]);
};

AES256.prototype.generateSecureIV = function (password, success, error) {
    exec(success, error, 'AES256', 'generateSecureIV', [password]);
};

var aES256 = new AES256();

module.exports = aES256;