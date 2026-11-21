import XCTest
import Foundation
import Darwin
@testable import TerminalMacCore

final class ExecSupportTests: XCTestCase {
    func testExecChannelParsing() throws {
        XCTAssertEqual(try ExecChannel.parse(nil), .auto)
        XCTAssertEqual(try ExecChannel.parse("auto"), .auto)
        XCTAssertEqual(try ExecChannel.parse("SSH"), .ssh)
        XCTAssertEqual(try ExecChannel.parse("agent"), .agent)
        XCTAssertThrowsError(try ExecChannel.parse("invalid"))
    }

    func testShellQuotingPreservesSpecialCharsAndUTF8() throws {
        let samples = [
            "echo 'a;b|c>d\"e'",
            "/tmp/测试目录/a;b|c>d\"e'f$(id)`uname` 空格.txt",
            "/Volumes/My Shared Files/"
        ]
        for sample in samples {
            let quoted = ShellQuoting.posixSingleQuote(sample)
            let out = try LocalProcessRunner.run(executable: "/bin/sh", arguments: ["-c", "printf '%s' \(quoted)"], timeout: 5)
            XCTAssertEqual(out.exitCode, 0)
            XCTAssertEqual(String(decoding: out.stdout, as: UTF8.self), sample)
        }
        XCTAssertEqual(ShellQuoting.remotePathExpression("~"), "\"$HOME\"")
        XCTAssertEqual(ShellQuoting.remotePathExpression("~/a b/c'd.txt"), "\"$HOME\"/'a b/c'\\''d.txt'")
    }

    func testDHCPLeaseAndARPParsing() {
        let leases = """
        {
        \tname=vm1
        \tip_address=192.168.64.5
        \thw_address=1,9a:3:7c:b4:47:6e
        \tlease=0x6afc5e8f
        }
        {
        \tname=vm1
        \tip_address=192.168.64.6
        \thw_address=1,9a:3:7c:b4:47:6e
        \tlease=0x6b01d532
        }
        """
        XCTAssertEqual(DHCPLeaseParser.normalizeMAC("1,9A:3:7C:B4:47:6E"), "9a:03:7c:b4:47:6e")
        XCTAssertEqual(DHCPLeaseParser.findIP(forMAC: "9a:03:7c:b4:47:6e", in: leases), "192.168.64.6")
        let arp = "? (192.168.64.6) at 9a:3:7c:b4:47:6e on bridge100 ifscope [bridge]\n"
        let rows = DHCPLeaseParser.parseARP(arp)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].ip, "192.168.64.6")
        XCTAssertEqual(rows[0].mac, "9a:03:7c:b4:47:6e")
    }

    func testLocalProcessRunnerCompoundCommandStdinAndTimeout() throws {
        let hi = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "echo hi"], timeout: 5)
        XCTAssertEqual(hi.exitCode, 0)
        XCTAssertEqual(String(decoding: hi.stdout, as: UTF8.self), "hi\n")

        let compound = try LocalProcessRunner.run(
            executable: "/bin/zsh",
            arguments: ["-c", #"echo 'a;b|c>d"e'; printf '%s\n' "$(echo nested)" | tr 'a-z' 'A-Z'; echo err >&2"#],
            timeout: 5
        )
        XCTAssertEqual(compound.exitCode, 0)
        XCTAssertEqual(String(decoding: compound.stdout, as: UTF8.self), "a;b|c>d\"e\nNESTED\n")
        XCTAssertEqual(String(decoding: compound.stderr, as: UTF8.self), "err\n")

        let stdinRes = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "cat"], stdin: Data("中文 ; | > \"\n".utf8), timeout: 5)
        XCTAssertEqual(stdinRes.exitCode, 0)
        XCTAssertEqual(String(decoding: stdinRes.stdout, as: UTF8.self), "中文 ; | > \"\n")

        let timed = try LocalProcessRunner.run(executable: "/bin/zsh", arguments: ["-c", "sleep 10"], timeout: 0.3)
        XCTAssertTrue(timed.timedOut)
    }

    func testMailboxAtomicClaimPreventsDuplicateDelivery() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tm-test-claim-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let writer = try Mailbox(root)
        let total = 30
        for i in 0..<total {
            let req = Request(action: "type", arguments: ["text": "cmd-\(i)"], timeout: 10)
            try writer.write(JSONEncoder().encode(req), named: "request-\(req.id.uuidString).json")
        }
        let r1 = try Mailbox(root)
        let r2 = try Mailbox(root)
        async let a: [UUID] = Task.detached {
            var ids: [UUID] = []
            while let batch = try? r1.requests(), !batch.isEmpty { ids += batch.map(\.id) }
            return ids
        }.value
        async let b: [UUID] = Task.detached {
            var ids: [UUID] = []
            while let batch = try? r2.requests(), !batch.isEmpty { ids += batch.map(\.id) }
            return ids
        }.value
        let all = await a + b
        XCTAssertEqual(all.count, total)
        XCTAssertEqual(Set(all).count, total)
    }
}
