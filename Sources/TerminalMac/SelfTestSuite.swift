import Foundation
import CryptoKit
import Darwin
import TerminalMacCore

/// Built-in hard-assertion self-test suite (`terminal-mac selftest`), runnable without Xcode.
@MainActor
enum SelfTestSuite {
    private static func check(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure("Selftest failed: \(message)") }
    }

    static func runAll() async throws -> [String: Any] {
        var passed: [String] = []

        func record(_ name: String, _ body: () async throws -> Void) async throws {
            try await body()
            passed.append(name)
        }

        try await record("unicode_events_special_chars_once") {
            let samples = [
                "echo 'a;b|c>d\"e'",
                "echo A; echo B",
                "ls -la \"/Volumes/My Shared Files/\"",
                "curl -fsSL https://usemagpie.ai/install.sh | sh",
                "echo $(uname -s) `id -un` $HOME 中文🚀\nsecond\tcol"
            ]
            for sample in samples {
                let events = UnicodeText.events(sample)
                var reconstructed = ""
                for ev in events {
                    switch ev {
                    case .returnKey: reconstructed.append("\n")
                    case .tabKey: reconstructed.append("\t")
                    case .unicode(let units): reconstructed.append(String(utf16CodeUnits: units, count: units.count))
                    }
                }
                try check(reconstructed == sample, "reconstructed mismatch for \(sample): got \(reconstructed)")
                try check(events.count == sample.count, "event count mismatch for \(sample): \(events.count) != \(sample.count)")
            }
        }

        try await record("unicode_chunks_backward_compat") {
            let text = "0123456789abcdefTARGET"
            let chunks = UnicodeText.chunks(text)
            try check(chunks.flatMap { $0 } == Array(text.utf16), "chunks flatMap mismatch")
            try check(chunks.count == 2, "expected 2 chunks")
        }

        try await record("shell_quoting_utf8_and_metachars") {
            let tricky = "/tmp/测试目录/a;b|c>d\"e'f$(id)`uname` 空格.txt"
            let quoted = ShellQuoting.posixSingleQuote(tricky)
            let out = try LocalProcessRunner.run(executable: "/bin/sh", arguments: ["-c", "printf '%s' \(quoted)"], timeout: 5)
            try check(out.exitCode == 0, "shell quote test exit != 0")
            try check(String(decoding: out.stdout, as: UTF8.self) == tricky, "shell quote round-trip mismatch")
            let tildeExpr = ShellQuoting.remotePathExpression("~/测试 'a;b'/file.txt")
            try check(tildeExpr.hasPrefix("\"$HOME\"/"), "tilde expansion broken: \(tildeExpr)")
        }

        try await record("dhcp_and_arp_parsers") {
            let leases = """
            {
            \tname=xsydexuniji
            \tip_address=192.168.64.5
            \thw_address=1,9a:3:7c:b4:47:6e
            \tlease=0x6afc5e8f
            }
            {
            \tname=xsydexuniji
            \tip_address=192.168.64.6
            \thw_address=1,9a:3:7c:b4:47:6e
            \tlease=0x6b01d532
            }
            """
            try check(DHCPLeaseParser.normalizeMAC("1,9A:3:7C:B4:47:6E") == "9a:03:7c:b4:47:6e", "MAC normalize failed")
            try check(DHCPLeaseParser.findIP(forMAC: "9a:03:7c:b4:47:6e", in: leases) == "192.168.64.6", "DHCP latest lease lookup failed")
            let arp = "? (192.168.64.6) at 9a:3:7c:b4:47:6e on bridge100 ifscope [bridge]\n"
            let parsedArp = DHCPLeaseParser.parseARP(arp)
            try check(parsedArp.count == 1 && parsedArp[0].ip == "192.168.64.6" && parsedArp[0].mac == "9a:03:7c:b4:47:6e", "ARP parse failed")
        }

        try await record("ssh_probe_banner_vs_reset") {
            // 1. Spin up a local listener that accepts and immediately closes (simulates disabled sshd reset).
            let resetPort = try startOneShotServer(payload: nil)
            try check(!SSHProbe.isSSHReady(host: "127.0.0.1", port: resetPort, timeout: 0.8), "SSHProbe must reject reset/empty connection")

            // 2. Spin up a local listener that sends an SSH-2.0 banner.
            let bannerPort = try startOneShotServer(payload: Data("SSH-2.0-OpenSSH_9.9\r\n".utf8))
            try check(SSHProbe.isSSHReady(host: "127.0.0.1", port: bannerPort, timeout: 0.8), "SSHProbe must accept valid SSH-2.0 banner")
        }

        try await record("mailbox_atomic_claim_no_duplicate_delivery") {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("tm-selftest-claim-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let writer = try Mailbox(root)
            let total = 40
            for idx in 0..<total {
                let req = Request(action: "type", arguments: ["text": "item-\(idx)"], timeout: 10)
                try writer.write(JSONEncoder().encode(req), named: "request-\(req.id.uuidString).json")
            }
            let readerA = try Mailbox(root)
            let readerB = try Mailbox(root)
            async let gotA: [UUID] = Task.detached {
                var ids: [UUID] = []
                while let batch = try? readerA.requests(), !batch.isEmpty { ids += batch.map(\.id) }
                return ids
            }.value
            async let gotB: [UUID] = Task.detached {
                var ids: [UUID] = []
                while let batch = try? readerB.requests(), !batch.isEmpty { ids += batch.map(\.id) }
                return ids
            }.value
            let all = await gotA + gotB
            try check(all.count == total, "expected \(total) claimed requests, got \(all.count)")
            try check(Set(all).count == total, "duplicate request delivery detected!")
        }

        try await record("exec_verbatim_metachars_stdin_and_timeout") {
            let hi = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "echo hi"], timeout: 5)
            try check(hi.exitCode == 0 && String(decoding: hi.stdout, as: UTF8.self) == "hi\n", "echo hi mismatch")

            let compoundCmd = #"echo 'a;b|c>d"e'; printf '%s\n' "$(echo nested)" | tr 'a-z' 'A-Z'; echo "err" >&2"#
            let compound = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", compoundCmd], timeout: 5)
            try check(compound.exitCode == 0, "compound exit != 0")
            try check(String(decoding: compound.stdout, as: UTF8.self) == "a;b|c>d\"e\nNESTED\n", "compound stdout mismatch: \(String(decoding: compound.stdout, as: UTF8.self))")
            try check(String(decoding: compound.stderr, as: UTF8.self) == "err\n", "compound stderr mismatch")

            let piped = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "cat"], stdin: Data("中文 stdin ; | > \"\n".utf8), timeout: 5)
            try check(piped.exitCode == 0 && String(decoding: piped.stdout, as: UTF8.self) == "中文 stdin ; | > \"\n", "stdin passthrough mismatch")

            let timed = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "sleep 10"], timeout: 0.3)
            try check(timed.timedOut, "expected timeout to trigger")
        }

        try await record("mailbox_exec_and_push_pull_roundtrip_md5") {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("tm-selftest-e2e-\(UUID().uuidString)")
            let exchangeDir = root.appendingPathComponent("exchange")
            let guestFS = root.appendingPathComponent("guest-fs")
            let hostFS = root.appendingPathComponent("host-fs")
            try FileManager.default.createDirectory(at: exchangeDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: guestFS, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: hostFS, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }

            let hostBox = try Mailbox(exchangeDir)
            let guestBox = try Mailbox(exchangeDir)

            // Spawn an in-process mock guest loop serving exec, push, pull over Mailbox.
            let guestTask = Task.detached {
                while !Task.isCancelled {
                    if let reqs = try? guestBox.requests() {
                        for req in reqs {
                            do {
                                switch req.action {
                                case "exec":
                                    let cmd = req.arguments["command"] ?? ""
                                    let stdinData = req.arguments["stdinFile"].flatMap { try? guestBox.read($0, limit: 16 * 1024 * 1024) }
                                    let out = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", cmd], stdin: stdinData, timeout: 10)
                                    let outName = "stdout-\(req.id.uuidString).bin"
                                    let errName = "stderr-\(req.id.uuidString).bin"
                                    try guestBox.write(out.stdout, named: outName)
                                    try guestBox.write(out.stderr, named: errName)
                                    try guestBox.respond(Reply(id: req.id, values: ["stdoutFile": outName, "stderrFile": errName, "exitCode": String(out.exitCode)]))
                                case "push":
                                    let file = req.arguments["file"] ?? ""
                                    let path = req.arguments["path"] ?? ""
                                    let data = try guestBox.read(file, limit: 64 * 1024 * 1024) ?? Data()
                                    let url = URL(fileURLWithPath: path)
                                    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                                    try data.write(to: url, options: .atomic)
                                    try guestBox.respond(Reply(id: req.id, values: ["path": url.path, "bytes": String(data.count)]))
                                case "pull":
                                    let path = req.arguments["path"] ?? ""
                                    let data = try Data(contentsOf: URL(fileURLWithPath: path))
                                    let file = "transfer-\(req.id.uuidString).bin"
                                    try guestBox.write(data, named: file)
                                    try guestBox.respond(Reply(id: req.id, values: ["file": file, "path": path, "bytes": String(data.count)]))
                                default:
                                    try guestBox.respond(Reply(id: req.id, error: "unsupported"))
                                }
                            } catch {
                                try? guestBox.respond(Reply(id: req.id, error: error.localizedDescription))
                            }
                        }
                    }
                    try? await Task.sleep(nanoseconds: 5_000_000)
                }
            }
            defer { guestTask.cancel() }

            let execRes = try await HostGuestTransport.execViaAgent(
                mailbox: hostBox,
                command: #"echo 'a;b|c>d"e'; echo $(printf 'ok')"#,
                stdin: nil,
                timeout: 10
            )
            try check(execRes.exitCode == 0 && execRes.channel == "agent", "agent exec failed")
            try check(execRes.stdout == "a;b|c>d\"e\nok\n", "agent exec stdout mismatch: \(execRes.stdout)")

            let specialName = "中文测试 'a;b|c>d\"e' $(id).txt"
            let srcFile = hostFS.appendingPathComponent(specialName)
            let payload = Data("第一行：中文与特殊符号 ; | > \" ' $() `backtick`\n第二行：🚀\u{0000}binary\n".utf8)
            try payload.write(to: srcFile)
            let guestDest = guestFS.appendingPathComponent("子目录").appendingPathComponent(specialName).path
            let pulledFile = hostFS.appendingPathComponent("pulled-\(specialName)")

            let pushed = try await HostGuestTransport.pushViaAgent(mailbox: hostBox, localURL: srcFile, remotePath: guestDest, mode: 0o644, timeout: 10)
            try check(pushed.bytes == payload.count, "push byte count mismatch")
            let pulled = try await HostGuestTransport.pullViaAgent(mailbox: hostBox, remotePath: guestDest, localURL: pulledFile, timeout: 10)
            try check(pulled.bytes == payload.count, "pull byte count mismatch")

            let srcMD5 = Insecure.MD5.hash(data: payload).map { String(format: "%02x", $0) }.joined()
            let dstData = try Data(contentsOf: pulledFile)
            let dstMD5 = Insecure.MD5.hash(data: dstData).map { String(format: "%02x", $0) }.joined()
            try check(srcMD5 == dstMD5, "push/pull MD5 mismatch: \(srcMD5) != \(dstMD5)")
        }

        try await record("offline_vm_exec_error_hints_agent_channel") {
            let home = FileManager.default.temporaryDirectory.appendingPathComponent("tm-selftest-offline-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: home) }
            let store = Store(root: home)
            let vmDir = try store.directory("offlinevm")
            try FileManager.default.createDirectory(at: vmDir.appendingPathComponent("exchange"), withIntermediateDirectories: true)
            let machine = Machine(name: "offlinevm", cpu: 4, memoryGiB: 4, diskGiB: 64, network: false, installed: true)
            try store.save(machine)
            // Acquire runtime.lock in a child process? Wait: flock is per-open-file-description on macOS,
            // so holding a separate fd locked with LOCK_EX makes CLI.isRunning return true!
            let lockFD = open(vmDir.appendingPathComponent("runtime.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
            try check(lockFD >= 0 && flock(lockFD, LOCK_EX | LOCK_NB) == 0, "failed to lock test runtime.lock")
            defer { flock(lockFD, LOCK_UN); close(lockFD) }
            var caughtMessage = ""
            do {
                _ = try await HostGuestTransport.exec(store: store, name: "offlinevm", command: "echo hi", timeout: 5, channel: .auto)
                throw Failure("Expected offline VM exec to fail with --channel agent hint")
            } catch {
                caughtMessage = error.localizedDescription
            }
            try check(caughtMessage.contains("offline") && caughtMessage.contains("--channel agent"),
                      "Offline error missing expected hint: \(caughtMessage)")
        }

        return [
            "ok": true,
            "passedCount": passed.count,
            "tests": passed
        ]
    }

    private static func startOneShotServer(payload: Data?) throws -> UInt16 {
        let serverFD = socket(AF_INET, SOCK_STREAM, 0)
        guard serverFD >= 0 else { throw Failure("Cannot create test socket") }
        var yes: Int32 = 1
        setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(serverFD, 4) == 0 else { close(serverFD); throw Failure("Cannot bind/listen test socket") }
        var assigned = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &assigned) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(serverFD, $0, &len)
            }
        }
        let port = UInt16(bigEndian: assigned.sin_port)
        DispatchQueue.global(qos: .userInitiated).async {
            defer { close(serverFD) }
            let client = accept(serverFD, nil, nil)
            guard client >= 0 else { return }
            if let payload {
                payload.withUnsafeBytes { ptr in
                    _ = Darwin.send(client, ptr.baseAddress, ptr.count, 0)
                }
                usleep(50_000)
            }
            close(client)
        }
        return port
    }
}
