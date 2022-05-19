import Fluent

struct CreateUser: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(User.schema)
            .id()
            .field("username", .string, .required)
            .field("password_hash", .data, .required)
            .field("salt", .data, .required)
            .field("salted_password_hash", .data, .required)
            .field("exchange_key", .data, .required)
            .field("signing_key", .data, .required)
            .create()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema(User.schema).delete()
    }
}
