var exec = require('cordova/exec');

var AES256 = function () {};

AES256.prototype.encrypt = function (secureKey, iv, value, success, error) {
    exec(success, error, 'AES256', 'encrypt', [secureKey, iv, value]);
};

AES256.prototype.decrypt = function (secureKey, iv, value, success, error) {
    exec(success, error, 'AES256', 'decrypt', [secureKey, iv, value]);
};

var aES256 = new AES256();

module.exports = aES256;