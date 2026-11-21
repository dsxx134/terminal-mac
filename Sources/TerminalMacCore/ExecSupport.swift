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

/// Deadlock-free subprocess runner with concurrent stdout/stderr draining, optional stdin piping, and hard timeout.
public enum LocalProcessRunner {
    public static func run(
        executable: String,
        arguments: [String],
        stdin: Data? = nil,
        environment: [String: String]? = nil,
        currentDirectory: URL? = nil,
        timeout: TimeInterval = 30,
        maxOutputBytes: Int = 32 * 1024 * 1024
    ) throws -> ProcessOutput {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment { process.environment = environment }
        if let currentDirectory { process.currentDirectoryURL = currentDirectory }

        let outPipe = Pipe()
        let errPipe = Pipe()
        let inPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        process.standardInput = stdin != nil ? inPipe : FileHandle.nullDevice

        final class Box: @unchecked Sendable {
            var data = Data()
            var timedOut = false
        }
        let outBox = Box()
        let errBox = Box()
        let timeoutBox = Box()

        let readGroup = DispatchGroup()
        let queue = DispatchQueue(label: "dev.terminal-mac.process-io", attributes: .concurrent)

        func drain(_ handle: FileHandle, into box: Box) {
            readGroup.enter()
            queue.async {
                defer { readGroup.leave(); try? handle.close() }
                var collected = Data()
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                    if collected.count < maxOutputBytes {
                        let remaining = maxOutputBytes - collected.count
                        collected.append(chunk.prefix(remaining))
                    }
                }
                box.data = collected
            }
        }

        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }

        try process.run()
        // Close parent-side pipe ends immediately so EOF propagates cleanly.
        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()
        if stdin != nil { try? inPipe.fileHandleForReading.close() }

        drain(outPipe.fileHandleForReading, into: outBox)
        drain(errPipe.fileHandleForReading, into: errBox)

        if let stdin {
            queue.async {
                let writer = inPipe.fileHandleForWriting
                defer { try? writer.close() }
                _ = fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1)
                if !stdin.isEmpty {
                    // Ignore SIGPIPE errors if child closes stdin early.
                    stdin.withUnsafeBytes { bytes in
                        var offset = 0
                        while offset < bytes.count {
                            let n = Darwin.write(writer.fileDescriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                            if n < 0 && errno == EINTR { continue }
                            if n <= 0 { break }
                            offset += n
                        }
                    }
                }
            }
        }

        let waitResult = done.wait(timeout: .now() + max(0.1, timeout))
        if waitResult == .timedOut {
            timeoutBox.timedOut = true
            process.terminate()
            if done.wait(timeout: .now() + 0.5) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + 1.0)
            }
        }
        readGroup.wait()

        let code: Int32
        if process.terminationReason == .uncaughtSignal {
            code = 128 + process.terminationStatus
        } else {
            code = process.terminationStatus
        }
        return ProcessOutput(stdout: outBox.data, stderr: errBox.data, exitCode: code, timedOut: timeoutBox.timedOut)
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
        if output.exitCode == 255 {
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
        if output.exitCode == 255 { throw SSHError.connectionFailed(stderr) }
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
    ) throws -> Int {
        let remoteExpr = ShellQuoting.remotePathExpression(remotePath)
        var args = baseArgs(host: host, user: user, keyPath: keyPath, port: port)
        args.append("--")
        args.append("cat -- \(remoteExpr)")
        let output = try LocalProcessRunner.run(executable: "/usr/bin/ssh", arguments: args, stdin: nil, timeout: timeout, maxOutputBytes: 64 * 1024 * 1024)
        if output.timedOut { throw SSHError.timedOut(Int(timeout.rounded())) }
        let stderr = String(decoding: output.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if output.exitCode == 255 { throw SSHError.connectionFailed(stderr) }
        guard output.exitCode == 0 else { throw Failure("SSH pull failed (exit \(output.exitCode)): \(stderr)") }
        var destination = localURL
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDir), isDir.boolValue {
            destination = destination.appendingPathComponent((remotePath as NSString).lastPathComponent)
        } else {
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        try output.stdout.write(to: destination, options: .atomic)
        return output.stdout.count
    }
}
