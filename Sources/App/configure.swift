import Fluent
import FluentSQLiteDriver
import Leaf
import Vapor

public func configure(_ app: Application) throws {
    app.http.server.configuration.port = 3000
//    app.http.server.configuration.hostname = "127.0.0.1"
    app.http.server.configuration.hostname = "0.0.0.0"
    
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))
    app.middleware.use(app.sessions.middleware)
    
    let currentDirectory = URL(fileURLWithPath: #file).deletingLastPathComponent()
    let sqlitePath = currentDirectory.appendingPathComponent("db").appendingPathExtension("sqlite")
    app.databases.use(.sqlite(.file(sqlitePath.path)), as: .sqlite)
    
    app.migrations.add(CreateUser())
    app.migrations.add(CreateMessage())
    app.migrations.add(CreateAsymmetricMessage())
    try app.autoMigrate().wait()
    
    app.views.use(.leaf)
    app.leaf.tags["user"] = UserSession()
    
    // register routes
    try routes(app)
}

struct UserSession: LeafTag {
    func render(_ ctx: LeafContext) throws -> LeafData {
        guard let request = ctx.request,
              !request.session.data["user_id"].isNil else {
            return .bool(false)
        }
        return .bool(true)
    }
}
