import Fluent
import Vapor

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Hello Vapor!"])
    }

    try app.register(collection: UserController())
    try app.register(collection: CaesarController())
    try app.register(collection: HashController())
    try app.register(collection: HmacController())
    try app.register(collection: MessageController())
    try app.register(collection: AsymmetricController())
}
