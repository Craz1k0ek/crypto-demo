import Vapor

private struct EncryptDTO: Decodable {
    let plaintext: String
    let key: Int
}

private struct DecryptDTO: Decodable {
    let ciphertext: String
    let key: Int
}

struct CaesarController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let caesar = routes.grouped("caesar")
        caesar.get(use: showCaesar)
        
        caesar.post("encrypt", use: encrypt)
        caesar.post("decrypt", use: decrypt)
    }
    
    private func showCaesar(request: Request) async throws -> View {
        return try await request.view.render("caesar", ["key": 1])
    }
    
    private func encrypt(request: Request) async throws -> Response {
        let dto = try request.content.decode(EncryptDTO.self)
        return try await request.view.render("caesar", [
            "plaintext": dto.plaintext,
            "ciphertext": App.encrypt(plaintext: dto.plaintext, key: dto.key),
            "key": "\(dto.key)"
        ]).encodeResponse(for: request)
    }
    
    private func decrypt(request: Request) async throws -> Response {
        let dto = try request.content.decode(DecryptDTO.self)
        return try await request.view.render("caesar", [
            "plaintext": App.decrypt(ciphertext: dto.ciphertext, key: dto.key),
            "ciphertext": dto.ciphertext,
            "key": "\(dto.key)"
        ]).encodeResponse(for: request)
    }
}

let characters: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

private func encrypt(plaintext: String, key: Int) -> String {
    String(plaintext.uppercased().map { value -> Character in
        guard let index = characters.firstIndex(of: value) else {
            return value
        }
        return characters[(index + key) % characters.count]
    })
}

private func decrypt(ciphertext: String, key: Int) -> String {
    String(ciphertext.uppercased().map { value -> Character in
        guard let index = characters.firstIndex(of: value) else {
            return value
        }
        return characters[(index - key + characters.count) % characters.count]
    })
}
