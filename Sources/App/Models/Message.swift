import Fluent
import Vapor

final class Message: Model, Content {
    static let schema = "messages"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "ciphertext")
    var ciphertext: Data
    
    @Parent(key: "sender")
    var sender: User
    
    @Parent(key: "receiver")
    var receiver: User
    
    init() {}
    
    init(id: UUID? = nil, message: String, password: String, sender: User, receiver: User) throws {
        self.id = id
        self.ciphertext = try AES.GCM.seal(Data(message.utf8), using: SymmetricKey.pbkdf2(password)).combined!
        self.$sender.id = try sender.requireID()
        self.$receiver.id = try receiver.requireID()
    }
}
