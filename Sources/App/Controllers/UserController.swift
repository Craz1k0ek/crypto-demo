import Fluent
import Vapor

struct UserDTO: Decodable {
    let username: String
    let password: String
}

struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let users = routes.grouped("user")
        
        users.get("login", use: showLogin)
        users.post("login", use: performLogin)
        users.get("logout", use: performLogout)
        
        users.get("register", use: showRegister)
        users.post("register", use: performRegister)
        
        users.get("list", use: showUserList)
        users.get("list", ":salt", use: showUserList)
        
        users.get("keys", use: showUserPublicKeys)
    }
}

// MARK: - Login & logout

extension UserController {
    private func showLogin(request: Request) async throws -> Response {
        if !request.session.data["user_id"].isNil {
            return request.redirect(to: "/")
        }
        return try await request.view.render("login").encodeResponse(for: request)
    }
    
    private func performLogin(request: Request) async throws -> Response {
        let dto = try request.content.decode(UserDTO.self)
        let user = try await User.query(on: request.db)
            .filter(\.$username == dto.username)
            .first()
        
        guard
            let user = user,
            user.verify(password: dto.password) else {
            return try await request.view.render("login", ["error": "Invalid credentials"]).encodeResponse(for: request)
        }
        
        request.session.data["user_id"] = try user.requireID().uuidString
        
        return request.redirect(to: try request.query.get(String?.self, at: ["origin"]) ?? "/")
    }
    
    private func performLogout(request: Request) async throws -> Response {
        request.session.destroy()
        return request.redirect(to: "/user/login")
    }
}

// MARK: - Registration

extension UserController {
    private func showRegister(request: Request) async throws -> Response {
        if !request.session.data["user_id"].isNil {
            return request.redirect(to: "/")
        }
        return try await request.view.render("register").encodeResponse(for: request)
    }
    
    private func performRegister(request: Request) async throws -> Response {
        let dto = try request.content.decode(UserDTO.self)
        
        guard try await User.query(on: request.db)
            .filter(\.$username == dto.username)
            .first().isNil else {
            return try await request.view.render("register", ["error": "Username already taken"]).encodeResponse(for: request)
        }
        
        let user = User(username: dto.username, password: dto.password)
        try await user.save(on: request.db)
        
        request.session.data["user_id"] = try user.requireID().uuidString
        return request.redirect(to: "/")
    }
}

// MARK: - List

struct UserDisplayDTO: Content {
    let username: String
    let passwordHash: String
    let salt: String
    let saltedPasswordHash: String
    
    init(_ user: User) {
        self.username = user.username
        self.passwordHash = user.passwordHash.hex.insert(separator: " ", every: 8)
        self.salt = user.salt.hex.insert(separator: " ", every: 8)
        self.saltedPasswordHash = user.saltedPasswordHash.hex.insert(separator: " ", every: 8)
    }
}

extension UserController {
    private func showUserList(request: Request) async throws -> Response {
        let users = try await User.query(on: request.db).all().map(UserDisplayDTO.init)
        return try await request.view.render(
            try request.query.get(Bool.self, at: ["salt"]) ? "user_list_salted" : "user_list",
            ["users": users]
        ).encodeResponse(for: request)
    }
    
    private func showUserPublicKeys(request: Request) async throws -> Response {
        guard let userID = request.session.data["user_id"] else {
            return request.redirect(to: "/user/login?origin=\(request.url.string)")
        }
        guard let user = try await User.find(UUID(uuidString: userID), on: request.db) else {
            return request.redirect(to: "/user/register")
        }
        return try await request.view.render("user_list_public_key", [
            "key_exchange": user.exchangeKey.hex.insert(separator: " ", every: 8),
            "key_signing": user.signingKey.hex.insert(separator: " ", every: 8)
        ]).encodeResponse(for: request)
    }
}
