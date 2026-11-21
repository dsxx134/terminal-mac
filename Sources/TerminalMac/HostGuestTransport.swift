import Foundation
import TerminalMacCore

public struct TransferResult: Codable, Equatable {
    public let ok: Bool
    public let channel: String
    public let localPath: String
    public let remotePath: String
    public let bytes: Int

    public func jsonDictionary() -> [String: Any] {
        [
            "ok": ok,
            "channel": channel,
            "localPath": localPath,
            "remotePath": remotePath,
            "bytes": bytes
        ]
    }
}

/// Shared host-side transport for `exec`, `push`, `pull`, and `ssh-setup` (used by both CLI and MCP).
/// Priority: SSH direct over VM network (with fast TCP + SSH banner probe), falling back to VirtioFS guest-agent mailbox.
@MainActor
enum HostGuestTransport {
    static let maxTransferBytes = 64 * 1024 * 1024

    static func exec(
        store: Store,
        name: String,
        command: String,
        stdin: Data? = nil,
        timeout: Int = 30,
        channel: ExecChannel = .auto,
        sshHost: String? = nil,
        sshUser: String? = nil,
        sshKey: String? = nil
    ) async throws -> ExecResult {
        guard !command.isEmpty else { throw Failure("Provide a command to execute") }
        let (machine, directory) = try requireRunningMachine(store: store, name: name)
        let mailbox = try Mailbox(directory.appendingPathComponent("exchange"))

        if !machine.network && channel != .agent {
            throw Failure("VM '\(name)' is offline; SSH exec is unavailable. Retry with --channel agent to execute over VirtioFS (works offline).")
        }

        if channel == .agent {
            return try await execViaAgent(mailbox: mailbox, command: command, stdin: stdin, timeout: timeout)
        }

        let target = await resolveSSHTarget(machine: machine, overrideHost: sshHost, overrideUser: sshUser, mailbox: mailbox)
        var sshFailureReason: String?

        if let host = target.host {
            if let sshKey, !sshKey.isEmpty, !SSHProbe.isSSHReady(host: host, timeout: 0.8) {
                _ = try? await setupSSHViaAgent(mailbox: mailbox, keyPath: sshKey, timeout: 4)
            }
            if SSHProbe.isSSHReady(host: host, timeout: 1.5) {
                do {
                    return try await runSSHExec(host: host, user: target.user, keyPath: sshKey, command: command, stdin: stdin, timeout: TimeInterval(timeout))
                } catch let error as SSHError {
                    if case .connectionFailed = error, let sshKey, !sshKey.isEmpty {
                        // Try injecting the key via guest helper once and retry SSH.
                        if (try? await setupSSHViaAgent(mailbox: mailbox, keyPath: sshKey, timeout: 4)) != nil {
                            do {
                                return try await runSSHExec(host: host, user: target.user, keyPath: sshKey, command: command, stdin: stdin, timeout: TimeInterval(timeout))
                            } catch let retryError as SSHError {
                                sshFailureReason = retryError.localizedDescription
                            }
                        } else {
                            sshFailureReason = error.localizedDescription
                        }
                    } else if case .timedOut = error {
                        throw error
                    } else {
                        sshFailureReason = error.localizedDescription
                    }
                }
            } else {
                sshFailureReason = "SSH port 22 on \(host) is closed or not responding with an SSH banner"
            }
        } else {
            sshFailureReason = "Could not discover guest IP address (VM may be offline or not yet leased via DHCP)"
        }

        if channel == .ssh {
            throw Failure("SSH exec unavailable for VM '\(name)': \(sshFailureReason ?? "unreachable"). Enable Remote Login inside the guest or retry with --channel agent to use the VirtioFS guest-agent channel.")
        }

        // Auto mode fallback to VirtioFS guest-agent mailbox.
        do {
            return try await execViaAgent(mailbox: mailbox, command: command, stdin: stdin, timeout: timeout)
        } catch {
            let reason = sshFailureReason ?? "unavailable"
            throw Failure("Both SSH (\(reason)) and VirtioFS guest-agent failed: \(error.localizedDescription)")
        }
    }

    static func push(
        store: Store,
        name: String,
        localPath: String,
        remotePath: String,
        timeout: Int = 60,
        channel: ExecChannel = .auto,
        sshHost: String? = nil,
        sshUser: String? = nil,
        sshKey: String? = nil
    ) async throws -> TransferResult {
        let localURL = URL(fileURLWithPath: (localPath as NSString).expandingTildeInPath)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: localURL.path, isDirectory: &isDir), !isDir.boolValue else {
            throw Failure("Local file does not exist or is a directory: \(localURL.path)")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: localURL.path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard size <= maxTransferBytes else {
            throw Failure("File exceeds maximum transfer size (64 MiB): \(localURL.path)")
        }
        let posixMode = (attributes[.posixPermissions] as? NSNumber)?.intValue

        let (machine, directory) = try requireRunningMachine(store: store, name: name)
        let mailbox = try Mailbox(directory.appendingPathComponent("exchange"))

        if !machine.network && channel != .agent {
            throw Failure("VM '\(name)' is offline; SSH push is unavailable. Retry with --channel agent to transfer over VirtioFS (works offline).")
        }

        if channel == .agent {
            return try await pushViaAgent(mailbox: mailbox, localURL: localURL, remotePath: remotePath, mode: posixMode, timeout: timeout)
        }

        let target = await resolveSSHTarget(machine: machine, overrideHost: sshHost, overrideUser: sshUser, mailbox: mailbox)
        var sshFailureReason: String?

        if let host = target.host, SSHProbe.isSSHReady(host: host, timeout: 1.5) {
            do {
                let bytes = try await Task.detached(priority: .userInitiated) {
                    try SSHClient.push(host: host, user: target.user, keyPath: sshKey, localURL: localURL, remotePath: remotePath, timeout: TimeInterval(timeout))
                }.value
                return TransferResult(ok: true, channel: "ssh", localPath: localURL.path, remotePath: remotePath, bytes: bytes)
            } catch let error as SSHError {
                if case .timedOut = error { throw error }
                sshFailureReason = error.localizedDescription
            }
        } else {
            sshFailureReason = target.host.map { "SSH port 22 on \($0) is unavailable" } ?? "Could not discover guest IP address"
        }

        if channel == .ssh {
            throw Failure("SSH push unavailable for VM '\(name)': \(sshFailureReason ?? "unreachable"). Retry with --channel agent.")
        }

        do {
            return try await pushViaAgent(mailbox: mailbox, localURL: localURL, remotePath: remotePath, mode: posixMode, timeout: timeout)
        } catch {
            throw Failure("Both SSH (\(sshFailureReason ?? "unavailable")) and VirtioFS guest-agent push failed: \(error.localizedDescription)")
        }
    }

    static func pull(
        store: Store,
        name: String,
        remotePath: String,
        localPath: String,
        timeout: Int = 60,
        channel: ExecChannel = .auto,
        sshHost: String? = nil,
        sshUser: String? = nil,
        sshKey: String? = nil
    ) async throws -> TransferResult {
        let localURL = URL(fileURLWithPath: (localPath as NSString).expandingTildeInPath)
        let (machine, directory) = try requireRunningMachine(store: store, name: name)
        let mailbox = try Mailbox(directory.appendingPathComponent("exchange"))

        if !machine.network && channel != .agent {
            throw Failure("VM '\(name)' is offline; SSH pull is unavailable. Retry with --channel agent to transfer over VirtioFS (works offline).")
        }

        if channel == .agent {
            return try await pullViaAgent(mailbox: mailbox, remotePath: remotePath, localURL: localURL, timeout: timeout)
        }

        let target = await resolveSSHTarget(machine: machine, overrideHost: sshHost, overrideUser: sshUser, mailbox: mailbox)
        var sshFailureReason: String?

        if let host = target.host, SSHProbe.isSSHReady(host: host, timeout: 1.5) {
            do {
                let pulled = try await Task.detached(priority: .userInitiated) {
                    try SSHClient.pull(host: host, user: target.user, keyPath: sshKey, remotePath: remotePath, localURL: localURL, timeout: TimeInterval(timeout))
                }.value
                return TransferResult(ok: true, channel: "ssh", localPath: pulled.localURL.path, remotePath: remotePath, bytes: pulled.bytes)
            } catch let error as SSHError {
                if case .timedOut = error { throw error }
                sshFailureReason = error.localizedDescription
            }
        } else {
            sshFailureReason = target.host.map { "SSH port 22 on \($0) is unavailable" } ?? "Could not discover guest IP address"
        }

        if channel == .ssh {
            throw Failure("SSH pull unavailable for VM '\(name)': \(sshFailureReason ?? "unreachable"). Retry with --channel agent.")
        }

        do {
            return try await pullViaAgent(mailbox: mailbox, remotePath: remotePath, localURL: localURL, timeout: timeout)
        } catch {
            throw Failure("Both SSH (\(sshFailureReason ?? "unavailable")) and VirtioFS guest-agent pull failed: \(error.localizedDescription)")
        }
    }

    static func setupSSH(store: Store, name: String, keyPath: String?, timeout: Int = 15) async throws -> [String: String] {
        let (_, directory) = try requireRunningMachine(store: store, name: name)
        let mailbox = try Mailbox(directory.appendingPathComponent("exchange"))
        return try await setupSSHViaAgent(mailbox: mailbox, keyPath: keyPath, timeout: timeout)
    }

    // MARK: - Agent Mailbox Implementations

    static func execViaAgent(mailbox: Mailbox, command: String, stdin: Data?, timeout: Int) async throws -> ExecResult {
        var arguments: [String: String] = ["command": command]
        let requestID = UUID()
        let stdinName = "stdin-\(requestID.uuidString).bin"
        var wroteStdin = false
        if let stdin, !stdin.isEmpty {
            try mailbox.write(stdin, named: stdinName)
            arguments["stdinFile"] = stdinName
            wroteStdin = true
        }
        let request = Request(action: "exec", arguments: arguments, timeout: Double(timeout))
        let stdoutName = "stdout-\(request.id.uuidString).bin"
        let stderrName = "stderr-\(request.id.uuidString).bin"
        defer {
            if wroteStdin { mailbox.remove(stdinName) }
            mailbox.remove(stdoutName)
            mailbox.remove(stderrName)
        }
        let reply = try await mailbox.call(request)
        let stdoutData: Data
        if reply.values["stdoutFile"] == stdoutName, let data = try mailbox.read(stdoutName, limit: 32 * 1024 * 1024) {
            stdoutData = data
        } else {
            stdoutData = Data((reply.values["stdout"] ?? "").utf8)
        }
        let stderrData: Data
        if reply.values["stderrFile"] == stderrName, let data = try mailbox.read(stderrName, limit: 32 * 1024 * 1024) {
            stderrData = data
        } else {
            stderrData = Data((reply.values["stderr"] ?? "").utf8)
        }
        let exitCode = Int32(reply.values["exitCode"] ?? "0") ?? 0
        return ExecResult(
            stdout: String(decoding: stdoutData, as: UTF8.self),
            stderr: String(decoding: stderrData, as: UTF8.self),
            exitCode: exitCode,
            channel: "agent"
        )
    }

    static func pushViaAgent(mailbox: Mailbox, localURL: URL, remotePath: String, mode: Int?, timeout: Int) async throws -> TransferResult {
        let data = try Data(contentsOf: localURL)
        let transferName = "transfer-\(UUID().uuidString).bin"
        try mailbox.write(data, named: transferName)
        defer { mailbox.remove(transferName) }
        var args: [String: String] = [
            "file": transferName,
            "path": remotePath,
            "filename": localURL.lastPathComponent
        ]
        if let mode { args["mode"] = String(mode, radix: 8) }
        let reply = try await mailbox.call(Request(action: "push", arguments: args, timeout: Double(timeout)))
        let finalPath = reply.values["path"] ?? remotePath
        let bytes = Int(reply.values["bytes"] ?? "") ?? data.count
        return TransferResult(ok: true, channel: "agent", localPath: localURL.path, remotePath: finalPath, bytes: bytes)
    }

    static func pullViaAgent(mailbox: Mailbox, remotePath: String, localURL: URL, timeout: Int) async throws -> TransferResult {
        let request = Request(action: "pull", arguments: ["path": remotePath], timeout: Double(timeout))
        let transferName = "transfer-\(request.id.uuidString).bin"
        defer { mailbox.remove(transferName) }
        let reply = try await mailbox.call(request)
        guard reply.values["file"] == transferName,
              let data = try mailbox.read(transferName, limit: maxTransferBytes) else {
            throw Failure("Guest helper returned an invalid pull response")
        }
        var destination = localURL
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDir), isDir.boolValue {
            destination = destination.appendingPathComponent((remotePath as NSString).lastPathComponent)
        } else {
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        try data.write(to: destination, options: .atomic)
        let resolvedRemote = reply.values["path"] ?? remotePath
        return TransferResult(ok: true, channel: "agent", localPath: destination.path, remotePath: resolvedRemote, bytes: data.count)
    }

    private static func setupSSHViaAgent(mailbox: Mailbox, keyPath: String?, timeout: Int) async throws -> [String: String] {
        var args: [String: String] = [:]
        if let keyPath, !keyPath.isEmpty {
            args["publicKey"] = try SSHClient.resolvePublicKey(from: keyPath)
        }
        let reply = try await mailbox.call(Request(action: "ssh-setup", arguments: args, timeout: Double(timeout)))
        return reply.values
    }

    // MARK: - Discovery & Validation Helpers

    private static func requireRunningMachine(store: Store, name: String) throws -> (Machine, URL) {
        let machine = try store.load(name)
        let directory = try store.directory(name)
        guard CLI.isRunning(directory) else {
            throw Failure("VM '\(name)' is stopped. Start it with: terminal-mac start \(name)")
        }
        return (machine, directory)
    }

    private static func resolveSSHTarget(machine: Machine, overrideHost: String?, overrideUser: String?, mailbox: Mailbox) async -> (host: String?, user: String?) {
        var host = (overrideHost?.isEmpty == false ? overrideHost : nil) ?? machine.sshHost
        var user = (overrideUser?.isEmpty == false ? overrideUser : nil) ?? machine.sshUser

        if host == nil, let mac = machine.macAddress {
            if let leases = try? String(contentsOfFile: "/var/db/dhcpd_leases", encoding: .utf8),
               let leased = DHCPLeaseParser.findIP(forMAC: mac, in: leases) {
                host = leased
            }
            if host == nil, let arpOut = try? LocalProcessRunner.run(executable: "/usr/sbin/arp", arguments: ["-an"], timeout: 2) {
                let text = String(decoding: arpOut.stdout, as: UTF8.self)
                if let normalized = DHCPLeaseParser.normalizeMAC(mac),
                   let hit = DHCPLeaseParser.parseARP(text).first(where: { $0.mac == normalized }) {
                    host = hit.ip
                }
            }
        }

        // Ask guest helper briefly for IP/user if still missing (works even for older VMs without saved MAC).
        if host == nil || user == nil {
            if let status = try? await mailbox.call(Request(action: "status", timeout: 1.5)) {
                if host == nil, let guestIP = status.values["ip"], !guestIP.isEmpty { host = guestIP }
                if user == nil, let guestUser = status.values["user"], !guestUser.isEmpty { user = guestUser }
            }
        }
        return (host, user)
    }

    private static func runSSHExec(host: String, user: String?, keyPath: String?, command: String, stdin: Data?, timeout: TimeInterval) async throws -> ExecResult {
        try await Task.detached(priority: .userInitiated) {
            try SSHClient.exec(host: host, user: user, keyPath: keyPath, command: command, stdin: stdin, timeout: timeout)
        }.value
    }
}
