import Fluent
import Vapor

final class User: Model, Content {
    static let schema = "users"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "username")
    var username: String
    
    @Field(key: "password_hash")
    var passwordHash: Data
    
    @Field(key: "salt")
    var salt: Data
    
    @Field(key: "salted_password_hash")
    var saltedPasswordHash: Data
    
    @Field(key: "exchange_key")
    var exchangeKey: Data
    
    @Field(key: "signing_key")
    var signingKey: Data
    
    init() {}
    
    init(id: UUID? = nil, username: String, password: String) {
        self.id = id
        self.username = username
        
        let utf8Password = Data(password.utf8)
        
        // One shot hash
        self.passwordHash = Data(SHA256.hash(data: utf8Password))
        
        let salt = Data((0 ..< 16).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) })
        
        // Accumulative hashing
        var hasher = SHA256()
        hasher.update(data: salt)
        hasher.update(data: utf8Password)
        
        self.salt = salt
        self.saltedPasswordHash = Data(hasher.finalize())
        
        self.exchangeKey = P256.KeyAgreement.PrivateKey().x963Representation
        self.signingKey = P256.Signing.PrivateKey().x963Representation
    }
    
    func verify(password: String) -> Bool {
        let utf8Password = Data(password.utf8)
        
        let passwordHash = Data(SHA256.hash(data: utf8Password))
        
        var hasher = SHA256()
        hasher.update(data: salt)
        hasher.update(data: utf8Password)
        
        let saltedPasswordHash = Data(hasher.finalize())
        
        return self.passwordHash == passwordHash && self.saltedPasswordHash == saltedPasswordHash
    }
}
