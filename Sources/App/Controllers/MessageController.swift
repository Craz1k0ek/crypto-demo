import Fluent
import Vapor

private struct MessageDTO: Decodable {
    let message: String
    let password: String
    let recipient: UUID
    
    enum Keys: String, CodingKey {
        case message, password, recipient
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        
        self.message = try container.decode(String.self, forKey: .message)
        self.password = try container.decode(String.self, forKey: .password)
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

private struct MessageDisplay: Content {
    let sender: String
    let id: UUID
    
    init(_ message: Message) {
        self.sender = message.sender.username
        self.id = message.id!
    }
}

private struct MessageOpenDTO: Decodable {
    let password: String
}

struct MessageController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let messages = routes.grouped("messages")
        
        messages.get("", use: showMessages)
        
        messages.get("send", use: showSendMessage)
        messages.post("send", use: performSendMessage)
        
        messages.get(":id", "open", use: showOpenMessage)
        messages.post(":id", "open", use: performOpenMessage)
        
        messages.get(":id", "delete", use: performDeleteMessage)
    }
    
    private func showMessages(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let messages = try await Message.query(on: request.db)
            .with(\.$sender)
            .filter(\.$receiver.$id == user.requireID())
            .all()
            .map(MessageDisplay.init)
        
        return try await request.view.render("messages", ["messages": messages]).encodeResponse(for: request)
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
        
        return try await request.view.render("message_send", [
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
        
        let dto = try request.content.decode(MessageDTO.self)
        
        guard let recipient = try await User.find(dto.recipient, on: request.db) else {
            throw Abort(.notFound, reason: "The user could not be found")
        }
        
        let message = try Message(message: dto.message, password: dto.password, sender: user, receiver: recipient)
        try await message.save(on: request.db)
        
        return request.redirect(to: "/messages/send")
    }
    
    private func showOpenMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let identifier = request.parameters.get("id", as: UUID.self)
        guard let message = try await Message.find(identifier, on: request.db) else {
            throw Abort(.notFound, reason: "The requested message could not be found")
        }
        guard message.$receiver.id == (try user.requireID()) else {
            throw Abort(.forbidden)
        }
        return try await request.view.render("message_open", ["message": message]).encodeResponse(for: request)
    }
    
    private func performOpenMessage(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        
        let identifier = request.parameters.get("id", as: UUID.self)
        guard let message = try await Message.find(identifier, on: request.db) else {
            throw Abort(.notFound, reason: "The requested message could not be found")
        }
        guard message.$receiver.id == (try user.requireID()) else {
            throw Abort(.forbidden)
        }
        
        let password = try request.content.decode(MessageOpenDTO.self).password
        let key = SymmetricKey.pbkdf2(password)
        let sealedBox = try AES.GCM.SealedBox(combined: message.ciphertext)
        
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(sealedBox, using: key)
        } catch {
            return try await request.view.render("message_open", ["error": "The password is incorrect"]).encodeResponse(for: request)
        }
        
        try await message.$sender.load(on: request.db)
        
        return try await request.view.render("message_detail", [
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
        guard let message = try await Message.find(identifier, on: request.db) else {
            throw Abort(.notFound, reason: "The requested message could not be found")
        }
        guard message.$receiver.id == (try user.requireID()) else {
            throw Abort(.forbidden)
        }
        try await message.delete(on: request.db)
        return request.redirect(to: "/messages")
    }
}
