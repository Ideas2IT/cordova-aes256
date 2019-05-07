import CommonCrypto;
class PBKDF2 {

    // Generates the key with specified length from the given password using pbkdf2 algorithm
    public class func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
        let passwordData = password.data(using: .utf8)!
        let saltData = salt.data(using: .utf8)!
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)

        var localDerivedKeyData = derivedKeyData

        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            saltData.withUnsafeBytes { saltBytes in

                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordData.count,
                    saltBytes, saltData.count,
                    hash,
                    UInt32(rounds),
                    derivedKeyBytes, localDerivedKeyData.count)
            }
        }
        if (derivationStatus != kCCSuccess) {
            return nil;
        }

        return PBKDF2.toHex(derivedKeyData)
    }

    // Converts data to a hexadecimal string
    private class func toHex(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
