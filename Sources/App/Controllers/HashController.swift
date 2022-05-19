import Vapor

private struct HashDTO: Decodable {
    let message: String
}

struct HashController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("hash", use: showHash)
        routes.post("hash", use: performHash)
    }
    
    private func showHash(request: Request) async throws -> View {
        return try await request.view.render("hash")
    }
    
    private func performHash(request: Request) async throws -> View {
        let dto = try request.content.decode(HashDTO.self)
        
        return try await request.view.render("hash", [
            "message": dto.message,
            "md5": Insecure.MD5.hash(data: Data(dto.message.utf8)).hex.insert(separator: " ", every: 8),
            "sha1": Insecure.SHA1.hash(data: Data(dto.message.utf8)).hex.insert(separator: " ", every: 8),
            "sha256": SHA256.hash(data: Data(dto.message.utf8)).hex.insert(separator: " ", every: 8),
            "sha384": SHA384.hash(data: Data(dto.message.utf8)).hex.insert(separator: " ", every: 8),
            "sha512": SHA512.hash(data: Data(dto.message.utf8)).hex.insert(separator: " ", every: 8)
        ])
    }
}
