@objc(AES256) class AES256 : CDVPlugin {
    func encrypt(_ command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while performing Encryption"
        )
        
        let secureKey = command.arguments[0] as? String ?? ""
        let iv = command.arguments[1] as? String ?? ""
        let value = command.arguments[2] as? String ?? ""
        
        
        let encrypted = AES256CBC.encryptString(value, password: secureKey, iv: iv)
        
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
    
        self.commandDelegate!.send(
            pluginResult, 
            callbackId: command.callbackId
        )
    }
    
    func decrypt(_ command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while performing Decryption"
        )
        
        let secureKey = command.arguments[0] as? String ?? ""
        let iv = command.arguments[1] as? String ?? ""
        let value = command.arguments[2] as? String ?? ""
        
        
        let decrypted = AES256CBC.decryptString(value, password: secureKey, iv: iv)
        
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: decrypted)
        
        self.commandDelegate!.send(
            pluginResult,
            callbackId: command.callbackId
        )
    }
}
