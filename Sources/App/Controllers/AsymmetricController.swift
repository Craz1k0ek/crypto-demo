import Fluent
import Vapor

private struct SignDTO: Decodable {
    let message: String
}

private struct VerifyDTO: Decodable {
    let message: String
    let signature: String
}

private struct AsymmetricMessageDisplay: Content {
    let sender: String
    let id: UUID
    
    init(_ message: AsymmetricMessage) {
        self.sender = message.sender.username
        self.id = message.id!
    }
}

private struct AsymmetricSendDTO: Decodable {
    let message: String
    let recipient: UUID
    
    enum Keys: String, CodingKey {
        case message, recipient
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        
        self.message = try container.decode(String.self, forKey: .message)
        do {
            self.recipient = try container.decode(UUID.self, forKey: .recipient)
        } catch {
            let uuidStr = try container.decode(String.self, forKey: .recipient)
            guard let uuid = UUID(uuidString: uuidStr) else {
                throw DecodingError.dataCorruptedError(forKey: Keys.recipient, in: container, debugDescription: "Cannot convert value to String or UUID")
            }
            self.recipient = uuid
        }
    }
}

struct AsymmetricController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let asymmetric = routes.grouped("asymmetric")
        
        asymmetric.get("sign", use: showSign)
        asymmetric.post("sign", use: performSign)
        
        asymmetric.get("verify", use: showVerify)
        asymmetric.post("verify", use: performVerify)
        
        let messages = asymmetric.grouped("messages")
        
        messages.get(use: showMessages)
        messages.get("send", use: showSendMessage)
        messages.post("send", use: performSendMessage)
        
        messages.get(":id", "open", use: showOpenMessage)
        messages.get(":id", "delete", use: performDeleteMessage)
    }
    
    private func showSign(request: Request) async throws -> View {
        return try await request.view.render("asymmetric_sign")
    }
    
    private func performSign(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let dto = try request.content.decode(SignDTO.self)
        let message = Data(dto.message.utf8)
        
        let signingKey = try P256.Signing.PrivateKey(x963Representation: user.signingKey)
        let signature = try signingKey.signature(for: message).derRepresentation.hex.insert(separator: " ", every: 8)
        
        return try await request.view.render("asymmetric_sign", [
            "message": dto.message,
            "signature": signature
        ]).encodeResponse(for: request)
    }
    
    private func showVerify(request: Request) async throws -> View {
        return try await request.view.render("asymmetric_verify")
    }
    
    private func performVerify(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let dto = try request.content.decode(VerifyDTO.self)
        let message = Data(dto.message.utf8)
        
        guard let signatureData = Data(hexString: dto.signature.replacingOccurrences(of: " ", with: "")) else {
            return try await request.view.render("asymmetric_verify", [
                "error": "The signature could not be reconstructed; Only hex encoded data is supported."
            ]).encodeResponse(for: request)
        }
        
        let signature = try P256.Signing.ECDSASignature(
            derRepresentation: signatureData
        )
        
        let verifyKey = try P256.Signing.PrivateKey(x963Representation: user.signingKey).publicKey
        
        let isValid = verifyKey.isValidSignature(signature, for: message)
        
        var context = [
            "message": dto.message,
            "signature": dto.signature,
        ]
        
        if isValid {
            context["success"] = "The signature was successfully verified!"
        } else {
            context["error"] = "The signature could not be verified!"
        }
        
        return try await request.view.render("asymmetric_verify", context).encodeResponse(for: request)
    }
    
    private func showMessages(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let messages = try await AsymmetricMessage.query(on: request.db)
            .with(\.$sender)
            .filter(\.$receiver.$id == user.requireID())
            .all()
            .map(AsymmetricMessageDisplay.init)
        
        return try await request.view.render("asymmetric_messages", ["messages": messages]).encodeResponse(for: request)
    }
    
    private func showSendMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let recipients = try await User.query(on: request.db)
            .filter(\.$id != user.requireID())
            .all()
        
        return try await request.view.render("asymmetric_message_send", [
            "recipients": recipients
        ]).encodeResponse(for: request)
    }
    
    private func performSendMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let dto = try request.content.decode(AsymmetricSendDTO.self)
        
        guard let recipient = try await User.find(dto.recipient, on: request.db) else {
            throw Abort(.notFound, reason: "The user could not be found")
        }
        
        let message = try AsymmetricMessage(message: dto.message, sender: user, receiver: recipient)
        try await message.save(on: request.db)
        
        return request.redirect(to: "/asymmetric/messages/send")
    }
    
    private func showOpenMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let identifier = request.parameters.get("id", as: UUID.self)
        guard let message = try await AsymmetricMessage.find(identifier, on: request.db) else {
            throw Abort(.notFound, reason: "The requested message could not be found")
        }
        guard message.$receiver.id == (try user.requireID()) else {
            throw Abort(.forbidden)
        }
        
        try await message.$sender.load(on: request.db)
        try await message.$receiver.load(on: request.db)
        
        let senderKey = try P256.KeyAgreement.PrivateKey(x963Representation: message.sender.exchangeKey).publicKey
        let receiverKey = try P256.KeyAgreement.PrivateKey(x963Representation: message.receiver.exchangeKey)
        
        let sharedSecret = try receiverKey.sharedSecretFromKeyAgreement(with: senderKey)
        let sharedKey = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        
        let sealedBox = try AES.GCM.SealedBox(combined: message.ciphertext)
        
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(sealedBox, using: sharedKey)
        } catch {
            return try await request.view.render("asymmetric_message_open", [
                "error": "Could not open the message with exchanged keys"
            ]).encodeResponse(for: request)
        }
        
        return try await request.view.render("asymmetric_message_open", [
            "sender": message.sender.username,
            "message": String(data: plaintext, encoding: .utf8)!
        ]).encodeResponse(for: request)
    }
    
    private func performDeleteMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let identifier = request.parameters.get("id", as: UUID.self)
        guard let message = try await AsymmetricMessage.find(identifier, on: request.db) else {
            throw Abort(.notFound, reason: "The requested message could not be found")
        }
        guard message.$receiver.id == (try user.requireID()) else {
            throw Abort(.forbidden)
        }
        try await message.delete(on: request.db)
        return request.redirect(to: "/asymmetric/messages")
    }
}
