// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import dnssd

/// Finds the port this device's RemotePairing service listens on, for when Henge could not.
///
/// Since iOS 26 the device picks that port at boot and advertises it as `_remotepairing._tcp`; the fixed
/// 49152 StikJIT falls back to is closed then, so every attempt times out at 10.7.0.1:49152. Henge's own lookup
/// (RemotePairingPortDiscovery) connects to the service to learn its port, and on some devices that never
/// becomes ready. This reads the port from the service's SRV record with DNSServiceResolve instead, which
/// needs no connection.
///
/// Every iPhone on the Wi-Fi advertises the same service type, so a service only counts when it is this
/// device's own: seen on loopback, or its host resolves to an address of one of this device's interfaces.
/// Taking the first service that resolved used another phone's port on shared networks. With none of its
/// own found, the caller scans this device's ports instead (RSDPortScanner).
enum RSDPortResolver {
    struct Result {
        var port: UInt16?
        /// What happened, for the log: the port found, or why there is none.
        var detail: String
    }

    private static let serviceType = "_remotepairing._tcp"

    /// Blocks for at most `timeout`. Call it off the main thread.
    static func resolve(timeout: TimeInterval = 4) -> Result {
        let state = State()
        state.localAddresses = localAddresses()
        state.loopbackIndex = if_nametoindex("lo0")
        let queue = DispatchQueue(label: "com.henge.app.jit-helper.rsd-port")
        let context = Unmanaged.passRetained(state)
        defer { context.release() }

        var browseRef: DNSServiceRef?
        let browseError = DNSServiceBrowse(&browseRef, 0, 0, serviceType, "local.", browseCallback,
                                           context.toOpaque())
        guard browseError == kDNSServiceErr_NoError, let browseRef else {
            return Result(port: nil, detail: "browse could not start (\(describe(browseError)))")
        }
        state.queue = queue
        DNSServiceSetDispatchQueue(browseRef, queue)

        let found = state.done.wait(timeout: .now() + timeout) == .success
        // Tear down on the queue the callbacks run on, so none runs after its ref is gone.
        return queue.sync {
            DNSServiceRefDeallocate(browseRef)
            state.resolveRefs.forEach(DNSServiceRefDeallocate)
            state.resolveRefs.removeAll()
            state.addressRefs.forEach(DNSServiceRefDeallocate)
            state.addressRefs.removeAll()
            state.candidates.removeAll()
            state.finished = true
            if found, let port = state.port {
                return Result(port: port, detail: "resolved \(serviceType) to port \(port) on \(state.host ?? "?")")
            }
            var detail = "no port within \(Int(timeout))s: \(state.seen) service(s) seen"
            if !state.otherHosts.isEmpty {
                detail += ", none on this device (skipped \(state.otherHosts.sorted().joined(separator: ", ")))"
            }
            if let error = state.lastError { detail += ", last error \(describe(error))" }
            return Result(port: nil, detail: detail)
        }
    }

    /// Only touched on `queue` once the browse has started.
    private final class State {
        let done = DispatchSemaphore(value: 0)
        var queue: DispatchQueue?
        var resolveRefs: [DNSServiceRef] = []
        var addressRefs: [DNSServiceRef] = []
        /// Kept alive while their address lookups run; each lookup's context points at one.
        var candidates: [Candidate] = []
        /// Numeric addresses of this device's interfaces, without scope.
        var localAddresses: Set<String> = []
        var loopbackIndex: UInt32 = 0
        /// Hosts of services that resolved to another device, for the log.
        var otherHosts: Set<String> = []
        var seen = 0
        var port: UInt16?
        var host: String?
        var lastError: DNSServiceErrorType?
        var finished = false

        func finish(port: UInt16, host: String) {
            guard self.port == nil, !finished else { return }
            self.port = port
            self.host = host
            done.signal()
        }
    }

    /// A resolved service waiting for its host's addresses.
    private final class Candidate {
        unowned let state: State
        let port: UInt16
        let host: String
        var matched = false
        init(state: State, port: UInt16, host: String) {
            self.state = state
            self.port = port
            self.host = host
        }
    }

    private static let browseCallback: DNSServiceBrowseReply = { _, flags, interface, error, name, type, domain, context in
        guard let context else { return }
        let state = Unmanaged<State>.fromOpaque(context).takeUnretainedValue()
        guard !state.finished, state.port == nil else { return }
        guard error == kDNSServiceErr_NoError else {
            state.lastError = error
            return
        }
        guard (flags & kDNSServiceFlagsAdd) != 0, let name, let type, let domain else { return }
        state.seen += 1
        var resolveRef: DNSServiceRef?
        let resolveError = DNSServiceResolve(&resolveRef, 0, interface, name, type, domain, resolveCallback, context)
        guard resolveError == kDNSServiceErr_NoError, let resolveRef, let queue = state.queue else {
            state.lastError = resolveError
            return
        }
        state.resolveRefs.append(resolveRef)
        DNSServiceSetDispatchQueue(resolveRef, queue)
    }

    private static let resolveCallback: DNSServiceResolveReply = { _, _, interface, error, _, host, port, _, _, context in
        guard let context else { return }
        let state = Unmanaged<State>.fromOpaque(context).takeUnretainedValue()
        guard !state.finished, state.port == nil else { return }
        guard error == kDNSServiceErr_NoError else {
            state.lastError = error
            return
        }
        // The port arrives in network byte order.
        let value = UInt16(bigEndian: port)
        guard value != 0, let host else { return }
        let hostName = String(cString: host)
        // Only this device's own services are visible on loopback.
        if state.loopbackIndex != 0, interface == state.loopbackIndex {
            state.finish(port: value, host: hostName)
            return
        }
        // Otherwise the service's host must resolve to one of this device's addresses.
        let candidate = Candidate(state: state, port: value, host: hostName)
        state.candidates.append(candidate)
        var addressRef: DNSServiceRef?
        let lookupError = DNSServiceGetAddrInfo(&addressRef, 0, interface,
                                                DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6),
                                                host, addressCallback, Unmanaged.passUnretained(candidate).toOpaque())
        guard lookupError == kDNSServiceErr_NoError, let addressRef, let queue = state.queue else {
            state.lastError = lookupError
            return
        }
        state.addressRefs.append(addressRef)
        DNSServiceSetDispatchQueue(addressRef, queue)
    }

    private static let addressCallback: DNSServiceGetAddrInfoReply = { _, flags, _, error, _, address, _, context in
        guard let context else { return }
        let candidate = Unmanaged<Candidate>.fromOpaque(context).takeUnretainedValue()
        let state = candidate.state
        guard !state.finished, state.port == nil, !candidate.matched else { return }
        guard error == kDNSServiceErr_NoError, (flags & kDNSServiceFlagsAdd) != 0,
              let address, let text = numericHost(address) else { return }
        if state.localAddresses.contains(text) {
            candidate.matched = true
            state.otherHosts.remove(candidate.host)
            state.finish(port: candidate.port, host: candidate.host)
        } else {
            state.otherHosts.insert(candidate.host)
        }
    }

    /// This device's interface addresses, numeric and without scope.
    private static func localAddresses() -> Set<String> {
        var result: Set<String> = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return result }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            if let address = entry.pointee.ifa_addr, let text = numericHost(address) { result.insert(text) }
        }
        return result
    }

    /// An IPv4 or IPv6 address as text, without any "%scope".
    private static func numericHost(_ address: UnsafePointer<sockaddr>) -> String? {
        let family = Int32(address.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else { return nil }
        let length = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(address, length, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        let text = String(cString: buffer)
        return text.split(separator: "%", maxSplits: 1).first.map(String.init)
    }

    private static func describe(_ error: DNSServiceErrorType) -> String {
        switch Int(error) {
        case Int(kDNSServiceErr_PolicyDenied): return "PolicyDenied: Local Network access is off for Henge"
        case Int(kDNSServiceErr_NoAuth): return "NoAuth"
        case Int(kDNSServiceErr_ServiceNotRunning): return "ServiceNotRunning"
        default: return "DNSServiceErrorType \(error)"
        }
    }
}
