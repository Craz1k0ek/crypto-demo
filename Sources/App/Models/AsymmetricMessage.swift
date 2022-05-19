import Fluent
import Vapor

final class AsymmetricMessage: Model, Content {
    static let schema = "asymmetric_messages"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "ciphertext")
    var ciphertext: Data
    
    @Parent(key: "sender")
    var sender: User
    
    @Parent(key: "receiver")
    var receiver: User
    
    init() {}
    
    init(id: UUID? = nil, message: String, sender: User, receiver: User) throws {
        self.id = id
        
        let senderKey = try P256.KeyAgreement.PrivateKey(x963Representation: sender.exchangeKey)
        let receiverKey = try P256.KeyAgreement.PrivateKey(x963Representation: receiver.exchangeKey).publicKey
        
        let sharedSecret = try senderKey.sharedSecretFromKeyAgreement(with: receiverKey)
        let sharedKey = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        
        self.ciphertext = try AES.GCM.seal(Data(message.utf8), using: sharedKey).combined!
        self.$sender.id = try sender.requireID()
        self.$receiver.id = try receiver.requireID()
    }
}
