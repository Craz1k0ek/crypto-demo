import Foundation

extension Data {
    init?(hexString: String) {
        let count = hexString.count / 2
        var data = Data(capacity: count)
        var i = hexString.startIndex
        for _ in 0 ..< count {
            let j = hexString.index(after: i)
            if var byte = UInt8(hexString[i ... j], radix: 16) {
                data.append(&byte, count: 1)
            } else {
                return nil
            }
            i = hexString.index(after: j)
        }
        self = data
    }
}
