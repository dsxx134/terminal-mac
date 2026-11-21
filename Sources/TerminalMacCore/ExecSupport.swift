import Foundation
import Darwin

public enum ExecChannel: String, Codable, Equatable {
    case auto
    case ssh
    case agent

    public static func parse(_ raw: String?) throws -> ExecChannel {
        guard let raw, !raw.isEmpty else { return .auto }
        guard let channel = ExecChannel(rawValue: raw.lowercased()) else {
            throw Failure("Invalid --channel '\(raw)'. Expected auto, ssh, or agent.")
        }
        return channel
    }
}

public struct ExecResult: Codable, Equatable {
    public let stdout: String
    public let stderr: String
    public let exitCode: Int32
    public let channel: String

    public init(stdout: String, stderr: String, exitCode: Int32, channel: String) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitCode = exitCode
        self.channel = channel
    }

    public func jsonDictionary() -> [String: Any] {
        [
            "stdout": stdout,
            "stderr": stderr,
            "exitCode": Int(exitCode),
            "channel": channel
        ]
    }
}

public enum SSHError: LocalizedError, Equatable {
    case connectionFailed(String)
    case timedOut(Int)

    public var errorDescription: String? {
        switch self {
        case .connectionFailed(let detail):
            return detail.isEmpty ? "SSH connection failed" : "SSH connection failed: \(detail)"
        case .timedOut(let seconds):
            return "SSH command timed out after \(seconds)s"
        }
    }
}

public enum ShellQuoting {
    /// POSIX single-quote escaping: safe for arbitrary UTF-8, spaces, quotes, `;`, `|`, `>`, `$()`, and backticks.
    public static func posixSingleQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Shell path expression that preserves `~` / `~/` expansion while keeping the rest strictly literal.
    public static func remotePathExpression(_ path: String) -> String {
        if path == "~" { return "\"$HOME\"" }
        if path.hasPrefix("~/") {
            let suffix = String(path.dropFirst(2))
            return "\"$HOME\"/" + posixSingleQuote(suffix)
        }
        return posixSingleQuote(path)
    }
}

public struct DHCPLease: Equatable {
    public let name: String?
    public let ipAddress: String
    public let macAddress: String
    public let leaseExpiry: UInt64

    public init(name: String?, ipAddress: String, macAddress: String, leaseExpiry: UInt64) {
        self.name = name
        self.ipAddress = ipAddress
        self.macAddress = macAddress
        self.leaseExpiry = leaseExpiry
    }
}

public enum DHCPLeaseParser {
    /// Normalizes MAC addresses such as `9a:3:7c:b4:47:6e` or `1,9A:03:7C:B4:47:6E` to `9a:03:7c:b4:47:6e`.
    public static func normalizeMAC(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let body = trimmed.split(separator: ",").last.map(String.init) ?? trimmed
        let parts = body.split(separator: ":")
        guard parts.count == 6 else { return nil }
        var normalized: [String] = []
        normalized.reserveCapacity(6)
        for part in parts {
            guard let byte = UInt8(part, radix: 16) else { return nil }
            normalized.append(String(format: "%02x", byte))
        }
        return normalized.joined(separator: ":")
    }

    public static func parseLeases(_ content: String) -> [DHCPLease] {
        var leases: [DHCPLease] = []
        var inBlock = false
        var name: String?
        var ip: String?
        var mac: String?
        var expiry: UInt64 = 0

        for rawLine in content.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line == "{" {
                inBlock = true; name = nil; ip = nil; mac = nil; expiry = 0
                continue
            }
            if line == "}" {
                if inBlock, let ip, let mac {
                    leases.append(DHCPLease(name: name, ipAddress: ip, macAddress: mac, leaseExpiry: expiry))
                }
                inBlock = false
                continue
            }
            guard inBlock, let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq])
            let value = String(line[line.index(after: eq)...])
            switch key {
            case "name": name = value
            case "ip_address": ip = value
            case "hw_address": mac = normalizeMAC(value)
            case "lease":
                if value.hasPrefix("0x") || value.hasPrefix("0X") {
                    expiry = UInt64(value.dropFirst(2), radix: 16) ?? 0
                } else {
                    expiry = UInt64(value) ?? 0
                }
            default: break
            }
        }
        return leases
    }

    public static func findIP(forMAC mac: String, in content: String) -> String? {
        guard let target = normalizeMAC(mac) else { return nil }
        return parseLeases(content)
            .filter { $0.macAddress == target }
            .max(by: { $0.leaseExpiry < $1.leaseExpiry })?
            .ipAddress
    }

    public static func parseARP(_ content: String) -> [(ip: String, mac: String)] {
        var results: [(ip: String, mac: String)] = []
        for rawLine in content.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            guard let openParen = line.firstIndex(of: "("),
                  let closeParen = line.firstIndex(of: ")"),
                  openParen < closeParen,
                  let atRange = line.range(of: " at ") else { continue }
            let ip = String(line[line.index(after: openParen)..<closeParen])
            let rest = line[atRange.upperBound...]
            let macToken = rest.split(separator: " ").first.map(String.init) ?? ""
            if let mac = normalizeMAC(macToken) {
                results.append((ip: ip, mac: mac))
            }
        }
        return results
    }
}

public enum GuestNetworkInfo {
    /// Returns the primary non-loopback IPv4 address (preferring en0/en*) on this macOS host/guest.
    public static func primaryIPv4() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(first) }
        var fallback: String?
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            guard let addr = current.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let flags = Int32(current.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            let name = String(cString: current.pointee.ifa_name)
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            guard inet_ntop(AF_INET, &sin, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { continue }
            let ip = String(cString: buffer)
            if ip.hasPrefix("169.254.") { continue }
            if name == "en0" { return ip }
            if name.hasPrefix("en") && fallback == nil { fallback = ip }
            else if fallback == nil { fallback = ip }
        }
        return fallback
    }
}

public enum SSHProbe {
    /// Fast non-blocking TCP connect + `SSH-` protocol banner check.
    /// Rejects ports that immediately reset (such as macOS when Remote Login is disabled).
    public static func isSSHReady(host: String, port: UInt16 = 22, timeout: TimeInterval = 1.5) -> Bool {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        hints.ai_family = AF_UNSPEC
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let info = result else { return false }
        defer { freeaddrinfo(info) }

        let deadline = Date().addingTimeInterval(max(0.1, timeout))
        var cursor: UnsafeMutablePointer<addrinfo>? = info
        while let current = cursor {
            defer { cursor = current.pointee.ai_next }
            let fd = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol)
            guard fd >= 0 else { continue }
            defer { close(fd) }
            let flags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

            let rc = Darwin.connect(fd, current.pointee.ai_addr, current.pointee.ai_addrlen)
            if rc != 0 && errno != EINPROGRESS { continue }
            if rc != 0 {
                let remainingMs = Int32(max(1, Int(deadline.timeIntervalSinceNow * 1000)))
                var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                guard poll(&pfd, 1, remainingMs) > 0 else { continue }
                var soError: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0, soError == 0 else { continue }
            }

            // Wait briefly for the server's `SSH-` identification banner.
            let remainingMs = Int32(max(1, Int(deadline.timeIntervalSinceNow * 1000)))
            var readPfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&readPfd, 1, remainingMs) > 0 else { continue }
            var banner = [UInt8](repeating: 0, count: 16)
            let count = Darwin.recv(fd, &banner, banner.count, 0)
            if count >= 4, String(decoding: banner.prefix(4), as: UTF8.self) == "SSH-" {
                return true
            }
        }
        return false
    }

    public static func isLocalSSHListening(timeout: TimeInterval = 0.5) -> Bool {
        isSSHReady(host: "127.0.0.1", port: 22, timeout: timeout)
    }
}

public struct ProcessOutput: Equatable {
    public let stdout: Data
    public let stderr: Data
    public let exitCode: Int32
    public let timedOut: Bool
}

public enum GuestPathResolver {
    /// Resolves guest filesystem paths consistently with SSH: relative paths anchor to `home`
    /// rather than a GUI `.app`'s `/` working directory.
    public static func resolve(_ rawPath: String, home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        if rawPath == "~" { return home }
        if rawPath.hasPrefix("~/") {
            return home.appendingPathComponent(String(rawPath.dropFirst(2))).standardizedFileURL
        }
        if rawPath.hasPrefix("~") {
            return URL(fileURLWithPath: (rawPath as NSString).expandingTildeInPath).standardizedFileURL
        }
        if rawPath.hasPrefix("/") {
            return URL(fileURLWithPath: rawPath).standardizedFileURL
        }
        return home.appendingPathComponent(rawPath).standardizedFileURL
    }
}

public enum ExecStdinReader {
    public static let defaultMaxBytes = 16 * 1024 * 1024

    private static func readLimited(fd: Int32, maxBytes: Int) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else {
                throw Failure("Failed to read stdin: \(String(cString: strerror(errno)))")
            }
            if count == 0 { break }
            if data.count + count > maxBytes {
                let mib = max(1, maxBytes / (1024 * 1024))
                throw Failure("stdin exceeds maximum size (\(mib) MiB)")
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    /// Reads optional stdin for `action exec`.
    /// - `--stdin <text>`: inline UTF-8 text (bounded by `maxBytes`).
    /// - `--stdin-file -`: explicitly blocks reading `stdinFD` until EOF (bounded by `maxBytes`).
    /// - `--stdin-file <path>`: reads a local file or FIFO until EOF (bounded by `maxBytes`).
    /// - Implicit fallback (neither flag): drains redirected regular files or immediately-ready pipes
    ///   without ever blocking on an idle parent pipe.
    public static func read(
        inline: String?,
        filePath: String?,
        stdinFD: Int32 = STDIN_FILENO,
        maxBytes: Int = defaultMaxBytes
    ) throws -> Data? {
        if inline != nil && filePath != nil {
            throw Failure("Cannot specify both --stdin and --stdin-file.")
        }
        if let inline {
            let data = Data(inline.utf8)
            guard data.count <= maxBytes else {
                let mib = max(1, maxBytes / (1024 * 1024))
                throw Failure("stdin exceeds maximum size (\(mib) MiB)")
            }
            return data
        }
        if let filePath {
            guard !filePath.isEmpty else {
                throw Failure("--stdin-file requires a file path or '-'")
            }
            if filePath == "-" {
                return try readLimited(fd: stdinFD, maxBytes: maxBytes)
            }
            let expanded = (filePath as NSString).expandingTildeInPath
            let fd = Darwin.open(expanded, O_RDONLY | O_CLOEXEC)
            guard fd >= 0 else {
                throw Failure("Cannot open --stdin-file '\(filePath)': \(String(cString: strerror(errno)))")
            }
            defer { Darwin.close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) != S_IFDIR else {
                throw Failure("--stdin-file cannot be a directory: \(filePath)")
            }
            return try readLimited(fd: fd, maxBytes: maxBytes)
        }
        guard isatty(stdinFD) == 0 else { return nil }
        var info = stat()
        guard fstat(stdinFD, &info) == 0 else { return nil }
        let kind = info.st_mode & S_IFMT
        if kind == S_IFREG {
            let data = try readLimited(fd: stdinFD, maxBytes: maxBytes)
            return data.isEmpty ? nil : data
        }
        if kind == S_IFIFO || kind == S_IFSOCK {
            var pfd = pollfd(fd: stdinFD, events: Int16(POLLIN), revents: 0)
            // Implicit piped stdin drains only when data is immediately ready; use `--stdin-file -` for slow pipes.
            guard poll(&pfd, 1, 20) > 0, (pfd.revents & Int16(POLLIN)) != 0 else { return nil }
            let data = try readLimited(fd: stdinFD, maxBytes: maxBytes)
            return data.isEmpty ? nil : data
        }
        return nil
    }
}

/// Deadlock-free subprocess runner with isolated process group, concurrent stdout/stderr/stdin I/O,
/// bounded post-exit pipe draining, and hard timeout process-group cleanup.
public enum LocalProcessRunner {
    private static func makeCloexecPipe() throws -> (readFD: Int32, writeFD: Int32) {
        var fds: [Int32] = [-1, -1]
        guard Darwin.pipe(&fds) == 0 else {
            throw Failure("Failed to create pipe: \(String(cString: strerror(errno)))")
        }
        _ = fcntl(fds[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(fds[1], F_SETFD, FD_CLOEXEC)
        return (fds[0], fds[1])
    }

    private static func setNonBlocking(_ fd: Int32) {
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    }

    private static func drainNonBlocking(_ fd: Int32, into data: inout Data, maxOutputBytes: Int) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n > 0 {
                if data.count < maxOutputBytes {
                    let remaining = maxOutputBytes - data.count
                    data.append(contentsOf: buffer.prefix(min(n, remaining)))
                }
                continue
            }
            if n == 0 { return true }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return false }
            return true
        }
    }

    public static func run(
        executable: String,
        arguments: [String],
        stdin: Data? = nil,
        environment: [String: String]? = nil,
        currentDirectory: URL? = nil,
        timeout: TimeInterval = 30,
        maxOutputBytes: Int = 32 * 1024 * 1024,
        postExitDrainTimeout: TimeInterval = 0.5
    ) throws -> ProcessOutput {
        let outPipe = try makeCloexecPipe()
        let errPipe = try makeCloexecPipe()
        let inPipe: (readFD: Int32, writeFD: Int32)? = stdin != nil ? try makeCloexecPipe() : nil
        let exitPipe = try makeCloexecPipe()

        var outReadFD = outPipe.readFD
        var outWriteFD = outPipe.writeFD
        var errReadFD = errPipe.readFD
        var errWriteFD = errPipe.writeFD
        var inReadFD = inPipe?.readFD ?? -1
        var inWriteFD = inPipe?.writeFD ?? -1
        var exitReadFD = exitPipe.readFD
        var exitWriteFD = exitPipe.writeFD

        func closeIfOpen(_ fd: inout Int32) {
            if fd >= 0 { Darwin.close(fd); fd = -1 }
        }
        defer {
            closeIfOpen(&outReadFD)
            closeIfOpen(&outWriteFD)
            closeIfOpen(&errReadFD)
            closeIfOpen(&errWriteFD)
            closeIfOpen(&inReadFD)
            closeIfOpen(&inWriteFD)
            closeIfOpen(&exitReadFD)
            closeIfOpen(&exitWriteFD)
        }

        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw Failure("Failed to initialize posix_spawn_file_actions")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }

        if inReadFD >= 0 {
            posix_spawn_file_actions_adddup2(&actions, inReadFD, STDIN_FILENO)
        } else {
            posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        }
        posix_spawn_file_actions_adddup2(&actions, outWriteFD, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&actions, errWriteFD, STDERR_FILENO)
        if let currentDirectory {
            _ = currentDirectory.path.withCString { path in
                posix_spawn_file_actions_addchdir_np(&actions, path)
            }
        }

        var attr: posix_spawnattr_t?
        guard posix_spawnattr_init(&attr) == 0 else {
            throw Failure("Failed to initialize posix_spawnattr")
        }
        defer { posix_spawnattr_destroy(&attr) }
        // Place child in its own process group (pgid == pid) and prevent leaking unrelated FDs.
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attr, 0)

        let argvStrings = [executable] + arguments
        var argv: [UnsafeMutablePointer<CChar>?] = argvStrings.map { strdup($0) }
        argv.append(nil)
        defer { for ptr in argv { free(ptr) } }

        let envStrings = (environment ?? ProcessInfo.processInfo.environment).map { "\($0.key)=\($0.value)" }
        var envp: [UnsafeMutablePointer<CChar>?] = envStrings.map { strdup($0) }
        envp.append(nil)
        defer { for ptr in envp { free(ptr) } }

        var childPID: pid_t = 0
        let spawnRC = executable.withCString { execPath in
            posix_spawn(&childPID, execPath, &actions, &attr, &argv, &envp)
        }
        guard spawnRC == 0 else {
            throw Failure("Failed to launch \(executable): \(String(cString: strerror(spawnRC)))")
        }

        // Close parent copies of child-side pipe ends immediately so EOF propagates cleanly.
        closeIfOpen(&outWriteFD)
        closeIfOpen(&errWriteFD)
        closeIfOpen(&inReadFD)

        setNonBlocking(outReadFD)
        setNonBlocking(errReadFD)
        setNonBlocking(exitReadFD)
        if inWriteFD >= 0 {
            setNonBlocking(inWriteFD)
            _ = fcntl(inWriteFD, F_SETNOSIGPIPE, 1)
            if stdin?.isEmpty == true {
                closeIfOpen(&inWriteFD)
            }
        }

        // Reap child on a detached queue and write the raw waitpid status through exitPipe.
        let notifyWriteFD = exitWriteFD
        exitWriteFD = -1
        DispatchQueue.global(qos: .userInitiated).async {
            defer { Darwin.close(notifyWriteFD) }
            var rawStatus: Int32 = 0
            while true {
                let waited = Darwin.waitpid(childPID, &rawStatus, 0)
                if waited < 0 && errno == EINTR { continue }
                if waited == childPID {
                    withUnsafeBytes(of: &rawStatus) { ptr in
                        _ = Darwin.write(notifyWriteFD, ptr.baseAddress, ptr.count)
                    }
                }
                break
            }
        }

        var stdoutData = Data()
        var stderrData = Data()
        var exitPayload = Data()
        var reapedStatus: Int32?
        var stdinOffset = 0
        let stdinBytes = stdin ?? Data()

        let now = { Date().timeIntervalSinceReferenceDate }
        let execDeadline = now() + max(0.1, timeout)
        var timedOut = false
        var sentTerm = false
        var termDeadline = Double.greatestFiniteMagnitude
        var sentKill = false
        var killDeadline = Double.greatestFiniteMagnitude
        var childExited = false
        var drainDeadline = Double.greatestFiniteMagnitude

        while true {
            let current = now()

            if !childExited {
                if !timedOut && current >= execDeadline {
                    timedOut = true
                    sentTerm = true
                    closeIfOpen(&inWriteFD)
                    _ = Darwin.kill(-childPID, SIGTERM)
                    _ = Darwin.kill(childPID, SIGTERM)
                    termDeadline = current + 0.5
                }
                if sentTerm && !sentKill && current >= termDeadline {
                    sentKill = true
                    _ = Darwin.kill(-childPID, SIGKILL)
                    _ = Darwin.kill(childPID, SIGKILL)
                    killDeadline = current + 1.0
                }
                if sentKill && current >= killDeadline {
                    break
                }
            }

            if childExited {
                if outReadFD < 0 && errReadFD < 0 { break }
                if current >= drainDeadline {
                    if outReadFD >= 0 { _ = drainNonBlocking(outReadFD, into: &stdoutData, maxOutputBytes: maxOutputBytes) }
                    if errReadFD >= 0 { _ = drainNonBlocking(errReadFD, into: &stderrData, maxOutputBytes: maxOutputBytes) }
                    break
                }
            }

            var pfds: [pollfd] = []
            var outIdx = -1
            var errIdx = -1
            var inIdx = -1
            var exitIdx = -1
            if outReadFD >= 0 {
                outIdx = pfds.count
                pfds.append(pollfd(fd: outReadFD, events: Int16(POLLIN), revents: 0))
            }
            if errReadFD >= 0 {
                errIdx = pfds.count
                pfds.append(pollfd(fd: errReadFD, events: Int16(POLLIN), revents: 0))
            }
            if inWriteFD >= 0 {
                inIdx = pfds.count
                pfds.append(pollfd(fd: inWriteFD, events: Int16(POLLOUT), revents: 0))
            }
            if exitReadFD >= 0 {
                exitIdx = pfds.count
                pfds.append(pollfd(fd: exitReadFD, events: Int16(POLLIN), revents: 0))
            }
            if pfds.isEmpty { break }

            var nextWake = Double.greatestFiniteMagnitude
            if !childExited {
                if !timedOut { nextWake = min(nextWake, execDeadline) }
                else if !sentKill { nextWake = min(nextWake, termDeadline) }
                else { nextWake = min(nextWake, killDeadline) }
            } else {
                nextWake = min(nextWake, drainDeadline)
            }
            let remainingMs = Int32(max(1, min(200, Int(((nextWake - current) * 1000.0).rounded(.up)))))
            let rc = pfds.withUnsafeMutableBufferPointer { buf in
                Darwin.poll(buf.baseAddress, nfds_t(buf.count), remainingMs)
            }
            if rc < 0 && errno == EINTR { continue }
            if rc <= 0 { continue }

            if outIdx >= 0 && (pfds[outIdx].revents & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 {
                if drainNonBlocking(outReadFD, into: &stdoutData, maxOutputBytes: maxOutputBytes) {
                    closeIfOpen(&outReadFD)
                }
            }
            if errIdx >= 0 && (pfds[errIdx].revents & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 {
                if drainNonBlocking(errReadFD, into: &stderrData, maxOutputBytes: maxOutputBytes) {
                    closeIfOpen(&errReadFD)
                }
            }
            if inIdx >= 0 && (pfds[inIdx].revents & Int16(POLLOUT | POLLHUP | POLLERR | POLLNVAL)) != 0 {
                if (pfds[inIdx].revents & Int16(POLLHUP | POLLERR | POLLNVAL)) != 0 {
                    closeIfOpen(&inWriteFD)
                } else {
                    var shouldCloseIn = false
                    stdinBytes.withUnsafeBytes { bytes in
                        while stdinOffset < bytes.count {
                            let n = Darwin.write(inWriteFD, bytes.baseAddress!.advanced(by: stdinOffset), bytes.count - stdinOffset)
                            if n > 0 {
                                stdinOffset += n
                                continue
                            }
                            if n < 0 && errno == EINTR { continue }
                            if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { break }
                            shouldCloseIn = true
                            break
                        }
                    }
                    if shouldCloseIn || stdinOffset >= stdinBytes.count {
                        closeIfOpen(&inWriteFD)
                    }
                }
            }
            if exitIdx >= 0 && (pfds[exitIdx].revents & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 {
                let done = drainNonBlocking(exitReadFD, into: &exitPayload, maxOutputBytes: 64)
                if done || exitPayload.count >= MemoryLayout<Int32>.size {
                    if exitPayload.count >= MemoryLayout<Int32>.size {
                        reapedStatus = exitPayload.withUnsafeBytes { $0.load(as: Int32.self) }
                    }
                    closeIfOpen(&exitReadFD)
                    closeIfOpen(&inWriteFD)
                    childExited = true
                    // Bound post-exit buffer draining so detached descendants inheriting stdio cannot hang us.
                    drainDeadline = now() + max(0.05, postExitDrainTimeout)
                }
            }
        }

        let code: Int32
        if let rawStatus = reapedStatus {
            let signal = rawStatus & 0x7f
            if signal == 0 {
                code = (rawStatus >> 8) & 0xff
            } else {
                code = 128 + signal
            }
        } else {
            code = timedOut ? 137 : -1
        }
        return ProcessOutput(stdout: stdoutData, stderr: stderrData, exitCode: code, timedOut: timedOut)
    }
}

public enum SSHClient {
    public static func resolvePublicKey(from keyPath: String) throws -> String {
        let expanded = (keyPath as NSString).expandingTildeInPath
        if expanded.hasPrefix("ssh-") || expanded.hasPrefix("ecdsa-") || expanded.hasPrefix("sk-") {
            return expanded.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if expanded.hasSuffix(".pub") {
            let content = try String(contentsOfFile: expanded, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !content.isEmpty else { throw Failure("SSH public key file is empty: \(expanded)") }
            return content
        }
        let pubSibling = expanded + ".pub"
        if FileManager.default.fileExists(atPath: pubSibling) {
            let content = try String(contentsOfFile: pubSibling, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            if !content.isEmpty { return content }
        }
        let output = try LocalProcessRunner.run(executable: "/usr/bin/ssh-keygen", arguments: ["-y", "-f", expanded], timeout: 10)
        guard output.exitCode == 0 else {
            let msg = String(decoding: output.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw Failure("Cannot derive public key from \(expanded): \(msg)")
        }
        let derived = String(decoding: output.stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !derived.isEmpty else { throw Failure("Derived SSH public key is empty: \(expanded)") }
        return derived
    }

    private static func baseArgs(host: String, user: String?, keyPath: String?, port: UInt16 = 22) -> [String] {
        var args = [
            "-T",
            "-p", String(port),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR"
        ]
        if let keyPath, !keyPath.isEmpty {
            let expanded = (keyPath as NSString).expandingTildeInPath
            let privatePath = expanded.hasSuffix(".pub") ? String(expanded.dropLast(4)) : expanded
            if FileManager.default.fileExists(atPath: privatePath) {
                args += ["-i", privatePath, "-o", "IdentitiesOnly=yes"]
            }
        }
        let target = (user?.isEmpty == false) ? "\(user!)@\(host)" : host
        args.append(target)
        return args
    }

    private static let sshTransportErrorPatterns: [String] = [
        "ssh:",
        "permission denied",
        "connection refused",
        "connection reset",
        "connection closed",
        "connection timed out",
        "operation timed out",
        "could not resolve",
        "no route to host",
        "network is unreachable",
        "kex_exchange_identification",
        "banner exchange",
        "host key verification",
        "remote host identification",
        "authentication failed",
        "too many authentication",
        "received disconnect",
        "client_loop:",
        "broken pipe"
    ]

    /// OpenSSH exits 255 on transport/auth errors AND forwards remote exit code 255 verbatim.
    /// Treat exit 255 as a transport failure only when stderr is non-empty and matches an SSH failure signature,
    /// so a remote `exit 255` never triggers an unintended agent fallback re-execution.
    public static func isConnectionFailure(exitCode: Int32, stderr: String) -> Bool {
        guard exitCode == 255 else { return false }
        let trimmed = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let lowered = trimmed.lowercased()
        return sshTransportErrorPatterns.contains { lowered.contains($0) }
    }

    public static func exec(
        host: String,
        user: String? = nil,
        keyPath: String? = nil,
        port: UInt16 = 22,
        command: String,
        stdin: Data? = nil,
        timeout: TimeInterval = 30
    ) throws -> ExecResult {
        var args = baseArgs(host: host, user: user, keyPath: keyPath, port: port)
        args.append("--")
        args.append(command)
        let output = try LocalProcessRunner.run(executable: "/usr/bin/ssh", arguments: args, stdin: stdin, timeout: timeout)
        if output.timedOut {
            throw SSHError.timedOut(Int(timeout.rounded()))
        }
        let stdout = String(decoding: output.stdout, as: UTF8.self)
        let stderr = String(decoding: output.stderr, as: UTF8.self)
        if isConnectionFailure(exitCode: output.exitCode, stderr: stderr) {
            throw SSHError.connectionFailed(stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return ExecResult(stdout: stdout, stderr: stderr, exitCode: output.exitCode, channel: "ssh")
    }

    public static func push(
        host: String,
        user: String? = nil,
        keyPath: String? = nil,
        port: UInt16 = 22,
        localURL: URL,
        remotePath: String,
        timeout: TimeInterval = 60
    ) throws -> Int {
        let data = try Data(contentsOf: localURL)
        let remoteExpr = ShellQuoting.remotePathExpression(remotePath)
        let filenameExpr = ShellQuoting.posixSingleQuote(localURL.lastPathComponent)
        let remoteScript = """
        dst=\(remoteExpr)
        if [ -d "$dst" ]; then dst="$dst"/\(filenameExpr); fi
        mkdir -p -- "$(dirname -- "$dst")" && cat > "$dst"
        """
        var args = baseArgs(host: host, user: user, keyPath: keyPath, port: port)
        args.append("--")
        args.append(remoteScript)
        let output = try LocalProcessRunner.run(executable: "/usr/bin/ssh", arguments: args, stdin: data, timeout: timeout)
        if output.timedOut { throw SSHError.timedOut(Int(timeout.rounded())) }
        let stderr = String(decoding: output.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if isConnectionFailure(exitCode: output.exitCode, stderr: stderr) { throw SSHError.connectionFailed(stderr) }
        guard output.exitCode == 0 else { throw Failure("SSH push failed (exit \(output.exitCode)): \(stderr)") }
        return data.count
    }

    public static func pull(
        host: String,
        user: String? = nil,
        keyPath: String? = nil,
        port: UInt16 = 22,
        remotePath: String,
        localURL: URL,
        timeout: TimeInterval = 60
    ) throws -> (localURL: URL, bytes: Int) {
        let remoteExpr = ShellQuoting.remotePathExpression(remotePath)
        var args = baseArgs(host: host, user: user, keyPath: keyPath, port: port)
        args.append("--")
        args.append("cat -- \(remoteExpr)")
        let output = try LocalProcessRunner.run(executable: "/usr/bin/ssh", arguments: args, stdin: nil, timeout: timeout, maxOutputBytes: 64 * 1024 * 1024)
        if output.timedOut { throw SSHError.timedOut(Int(timeout.rounded())) }
        let stderr = String(decoding: output.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if isConnectionFailure(exitCode: output.exitCode, stderr: stderr) { throw SSHError.connectionFailed(stderr) }
        guard output.exitCode == 0 else { throw Failure("SSH pull failed (exit \(output.exitCode)): \(stderr)") }
        var destination = localURL
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDir), isDir.boolValue {
            destination = destination.appendingPathComponent((remotePath as NSString).lastPathComponent)
        } else {
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        try output.stdout.write(to: destination, options: .atomic)
        return (localURL: destination, bytes: output.stdout.count)
    }
}
