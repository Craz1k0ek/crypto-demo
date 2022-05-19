import Fluent

struct CreateAsymmetricMessage: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(AsymmetricMessage.schema)
            .id()
            .field("ciphertext", .data, .required)
            .field("sender", .uuid, .references(User.schema, .id))
            .field("receiver", .uuid, .references(User.schema, .id))
            .create()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema(AsymmetricMessage.schema).delete()
    }
}
