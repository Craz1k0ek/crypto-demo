import Vapor

private struct HmacDTO: Decodable {
    let message: String
    let password: String
}

private struct HmacVerifyDTO: Decodable {
    let message: String
    let algorithm: String
    let hmac: String
    let password: String
    
    func verify(message: Data, hmac: Data, key: SymmetricKey) -> Bool {
        switch algorithm {
        case "md5":
            return HMAC<Insecure.MD5>.isValidAuthenticationCode(hmac, authenticating: message, using: key)
        case "sha1":
            return HMAC<Insecure.SHA1>.isValidAuthenticationCode(hmac, authenticating: message, using: key)
        case "sha256":
            return HMAC<SHA256>.isValidAuthenticationCode(hmac, authenticating: message, using: key)
        case "sha384":
            return HMAC<SHA384>.isValidAuthenticationCode(hmac, authenticating: message, using: key)
        case "sha512":
            return HMAC<SHA512>.isValidAuthenticationCode(hmac, authenticating: message, using: key)
        default:
            fatalError("Unsupported hash algorithm")
        }
    }
}

struct HmacController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("hmac", use: showHmac)
        routes.post("hmac", use: performHmac)
        
        routes.get("hmac", "verify", use: showVerifyHmac)
        routes.post("hmac", "verify", use: performVerifyHmac)
    }
    
    private func showHmac(request: Request) async throws -> View {
        return try await request.view.render("hmac")
    }
    
    private func performHmac(request: Request) async throws -> View {
        let dto = try request.content.decode(HmacDTO.self)
        let key = SymmetricKey.pbkdf2(dto.password)
        
        return try await request.view.render("hmac", [
            "message": dto.message,
            "key": dto.password,
            "md5": HMAC<Insecure.MD5>.authenticationCode(for: Data(dto.message.utf8), using: key).hex.insert(separator: " ", every: 8),
            "sha1": HMAC<Insecure.SHA1>.authenticationCode(for: Data(dto.message.utf8), using: key).hex.insert(separator: " ", every: 8),
            "sha256": HMAC<SHA256>.authenticationCode(for: Data(dto.message.utf8), using: key).hex.insert(separator: " ", every: 8),
            "sha384": HMAC<SHA384>.authenticationCode(for: Data(dto.message.utf8), using: key).hex.insert(separator: " ", every: 8),
            "sha512": HMAC<SHA512>.authenticationCode(for: Data(dto.message.utf8), using: key).hex.insert(separator: " ", every: 8)
        ])
    }
    
    private func showVerifyHmac(request: Request) async throws -> View {
        return try await request.view.render("hmac_verify")
    }
    
    private func performVerifyHmac(request: Request) async throws -> View {
        let dto = try request.content.decode(HmacVerifyDTO.self)
        
        let message = Data(dto.message.utf8)
        guard let hmac = Data(hexString: dto.hmac.replacingOccurrences(of: " ", with: "")) else {
            return try await request.view.render("hmac_verify", [
                "error": "The HMAC could not be reconstructed; Only hex encoded data is supported."
            ])
        }
        let key = SymmetricKey.pbkdf2(dto.password)
        
        let isValid = dto.verify(message: message, hmac: hmac, key: key)
        
        var context = [
            "message": dto.message,
            "hmac": dto.hmac,
            "password": dto.password,
        ]
        
        if isValid {
            context["success"] = "The HMAC was successfully verified!"
        } else {
            context["error"] = "The HMAC could not be verified!"
        }
        
        return try await request.view.render("hmac_verify", context)
    }
}
