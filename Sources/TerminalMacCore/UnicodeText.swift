/// UTF-16 payloads for literal keyboard events, keeping each Character intact.
public enum UnicodeText {
    /// A single literal input step delivered to CoreGraphics.
    public enum KeyEvent: Equatable {
        case returnKey
        case tabKey
        case unicode([UInt16])
    }

    /// Splits text into one event per Character so every symbol (including `;`, `|`, `>`, `"`, `'`,
    /// `$`, backticks, spaces, CJK and emoji) is posted cleanly once without multi-char chunk drops.
    public static func events(_ text: String) -> [KeyEvent] {
        var result: [KeyEvent] = []
        result.reserveCapacity(text.count)
        for character in text {
            if character == "\n" || character == "\r" || character == "\r\n" {
                result.append(.returnKey)
            } else if character == "\t" {
                result.append(.tabKey)
            } else {
                let units = Array(String(character).utf16)
                if !units.isEmpty { result.append(.unicode(units)) }
            }
        }
        return result
    }

    public static func chunks(_ text: String) -> [[UInt16]] {
        var result: [[UInt16]] = []
        var chunk: [UInt16] = []
        var lastTextStart: Int?
        func flush() {
            guard !chunk.isEmpty else { return }
            result.append(chunk)
            chunk.removeAll(keepingCapacity: true)
            lastTextStart = nil
        }
        for character in text {
            let units = Array(String(character).utf16)
            let separator = character.isNewline || character == "\t"
            if chunk.count + units.count > 16 {
                // Keep a separator from starting the next event by carrying the
                // preceding text Character with it, within the existing budget.
                if separator, let start = lastTextStart, start > 0,
                   chunk.count - start + units.count <= 16 {
                    result.append(Array(chunk[..<start]))
                    chunk = Array(chunk[start...])
                    lastTextStart = 0
                } else { flush() }
            }
            // A leading line break can consume the rest of an event's payload.
            // Keep embedded whitespace with its existing text chunk.
            if chunk.isEmpty && character.isNewline {
                result.append(units)
                continue
            }
            if !separator { lastTextStart = chunk.count }
            chunk += units
        }
        flush()
        return result
    }
}
