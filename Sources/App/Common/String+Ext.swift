extension String {
    func insert(separator: Character, every offset: Int) -> String {
        String(self.enumerated().map { $0 > 0 && $0 % offset == 0 ? [separator, $1] : [$1] }.joined())
    }
}
