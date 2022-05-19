extension Optional {
    var isNil: Bool {
        guard case .none = self else { return false }
        return true
    }
}
