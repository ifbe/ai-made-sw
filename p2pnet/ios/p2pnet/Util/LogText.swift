import Foundation

/// 日志里的 JSON 是一整块没有空格的字符，行断开是按「词」来的：
/// 这一块整体放不下时会被整个挪到下一行，看起来就像凭空空了一行。
///
/// 这里在 `{...}` 内部每个字符后面插一个零宽空格（U+200B）：它只增加换行点、
/// 本身不占宽度也不显示，于是 JSON 会正常接在前面文字后面、排到行尾再折行。
///
/// **只认 `{`，不认 `[`**：`[12:00:00.123]`、`[direct]` 这种方括号在普通日志里太常见，
/// 不当作 JSON 起点（JSON 数组都嵌在对象里，外层 `{` 已经把 depth 打开了）。
///
/// 只用于显示：复制走的是原始文本，不含这些零宽字符。
nonisolated func logDisplayText(_ line: String) -> String {
    guard line.contains("{") else { return line }
    var out = ""
    out.reserveCapacity(line.count + 32)
    var depth = 0
    for ch in line {
        out.append(ch)
        switch ch {
        case "{":
            depth += 1
            out.append("\u{200B}")
        case "}":
            if depth > 0 { depth -= 1 }
            if depth > 0 { out.append("\u{200B}") }
        default:
            if depth > 0 { out.append("\u{200B}") }
        }
    }
    return out
}
