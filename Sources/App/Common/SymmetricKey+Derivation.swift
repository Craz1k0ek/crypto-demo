import Foundation
import Vapor

//#if canImport(CommonCrypto)
//import CommonCrypto
//
//extension SymmetricKey {
//    static func pbkdf2(_ password: String, keyLength length: Int = 32) -> SymmetricKey {
//        var output = [UInt8](repeating: 0, count: 32)
//        let status = CCKeyDerivationPBKDF(
//            CCPBKDFAlgorithm(kCCPBKDF2),
//            password, password.count,
//            nil, 0,
//            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 310_000,
//            &output, output.count
//        )
//        guard status == kCCSuccess else {
//            fatalError("Failed to derive key: \(status)")
//        }
//        return SymmetricKey(data: Data(output))
//    }
//}
//#else

public struct PBKDF2 {
    private static func digest(_ password: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: password)))
    }

    private static func blockNumSaltThing(blockNum block: UInt) -> [UInt8] {
        var inti = [UInt8](repeating: 0, count: 4)
        inti[0] = UInt8((block >> 24) & 0xFF)
        inti[1] = UInt8((block >> 16) & 0xFF)
        inti[2] = UInt8((block >> 8) & 0xFF)
        inti[3] = UInt8(block & 0xFF)
        return inti
    }

    public static func calculate(_ password: Data, usingSalt salt: Data, iterating iterations: Int, keySize: Int = 32) -> Data {
        let blocks = UInt(ceil(Double(keySize) / Double(SHA256.byteCount)))
        var response = Data()
        
        for block in 1...blocks {
            var s = salt
            s.append(contentsOf: self.blockNumSaltThing(blockNum: block))
            
            var ui = digest(password, data: s)
            var u1 = ui
            
            for _ in 0..<iterations - 1 {
                u1 = digest(password, data: u1)
                ui = Data(zip(ui, u1).map { $0 ^ $1 })
            }
            
            response.append(contentsOf: ui)
        }
        
        return response
    }
    
    public static func calculate(_ password: String, usingSalt salt: Data, iterating iterations: Int, keySize: Int = 32) -> Data {
        return self.calculate(Data(password.utf8), usingSalt: salt, iterating: iterations, keySize: keySize)
    }
}

extension SymmetricKey {
    static func pbkdf2(_ password: String, keyLength length: Int = 32) -> SymmetricKey {
        return SymmetricKey(data: PBKDF2.calculate(password, usingSalt: Data(), iterating: 310_000, keySize: length))
    }
}

//#endif
