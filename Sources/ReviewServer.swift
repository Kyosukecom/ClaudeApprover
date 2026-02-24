import Foundation
import Network

/// Minimal HTTP server using NWListener on port 19482.
/// If another instance is already running on this port, this one exits immediately.
final class ReviewServer {
    private var listener: NWListener?
    private let manager: ReviewManager
    private let port: UInt16 = 19482

    init(manager: ReviewManager) {
        self.manager = manager
    }

    func start() {
        // Check if another instance is already running
        if isPortInUse() {
            print("[ReviewServer] Port \(port) already in use. Another instance is running. Exiting.")
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                exit(0)
            }
            return
        }

        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
        } catch {
            print("[ReviewServer] Failed to create listener: \(error)")
            return
        }

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }

        listener?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("[ReviewServer] Listening on port \(self.port)")
            case .failed(let error):
                print("[ReviewServer] Listener failed: \(error). Exiting.")
                // Exit so LaunchAgent can restart us
                exit(1)
            default:
                break
            }
        }

        listener?.start(queue: .global(qos: .userInitiated))
    }

    /// Check if port is already in use by sending a health check
    private func isPortInUse() -> Bool {
        let url = URL(string: "http://localhost:\(port)/api/health")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 2
        let semaphore = DispatchSemaphore(value: 0)
        var isRunning = false

        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 {
                isRunning = true
            }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()
        return isRunning
    }

    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: .global(qos: .userInitiated))

        // Read up to 1MB
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { [weak self] data, _, isComplete, error in
            guard let self, let data else {
                if let error { print("[ReviewServer] Receive error: \(error)") }
                connection.cancel()
                return
            }

            self.processHTTPRequest(data: data, connection: connection)
        }
    }

    private func processHTTPRequest(data: Data, connection: NWConnection) {
        guard let raw = String(data: data, encoding: .utf8) else {
            sendResponse(connection: connection, status: 400, body: #"{"error":"invalid encoding"}"#)
            return
        }

        // Parse HTTP request line
        let lines = raw.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else {
            sendResponse(connection: connection, status: 400, body: #"{"error":"empty request"}"#)
            return
        }

        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else {
            sendResponse(connection: connection, status: 400, body: #"{"error":"malformed request"}"#)
            return
        }

        let method = String(parts[0])
        let path = String(parts[1])

        // Route: POST /api/notify (fire-and-forget notification)
        if method == "POST" && (path == "/api/notify" || path == "/api/review") {
            // Extract body (after empty line)
            guard let bodyRange = raw.range(of: "\r\n\r\n") else {
                sendResponse(connection: connection, status: 400, body: #"{"error":"no body"}"#)
                return
            }
            let bodyString = String(raw[bodyRange.upperBound...])
            guard let bodyData = bodyString.data(using: .utf8) else {
                sendResponse(connection: connection, status: 400, body: #"{"error":"invalid body encoding"}"#)
                return
            }

            let decoder = JSONDecoder()
            guard let request = try? decoder.decode(ReviewRequest.self, from: bodyData) else {
                sendResponse(connection: connection, status: 400, body: #"{"error":"invalid JSON"}"#)
                return
            }

            // Add notification and return immediately (non-blocking)
            Task { @MainActor in
                self.manager.addNotification(request: request)
            }
            sendResponse(connection: connection, status: 200, body: #"{"status":"ok"}"#)
            return
        }

        // Route: POST /api/dismiss — tool was approved/executed, dismiss matching notification
        if method == "POST" && path == "/api/dismiss" {
            var toolUseId: String?
            if let bodyRange = raw.range(of: "\r\n\r\n") {
                let bodyString = String(raw[bodyRange.upperBound...])
                if let bodyData = bodyString.data(using: .utf8),
                   let json = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] {
                    toolUseId = json["tool_use_id"] as? String
                }
            }
            Task { @MainActor in
                if let id = toolUseId, !id.isEmpty {
                    self.manager.dismiss(toolUseId: id)
                } else {
                    self.manager.dismissAll()
                }
            }
            sendResponse(connection: connection, status: 200, body: #"{"status":"ok"}"#)
            return
        }

        // Route: GET /api/health
        if method == "GET" && path == "/api/health" {
            sendResponse(connection: connection, status: 200, body: #"{"status":"ok"}"#)
            return
        }

        sendResponse(connection: connection, status: 404, body: #"{"error":"not found"}"#)
    }

    private func sendResponse(connection: NWConnection, status: Int, body: String) {
        let statusText: String
        switch status {
        case 200: statusText = "OK"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        case 500: statusText = "Internal Server Error"
        default: statusText = "Unknown"
        }

        let response = "HTTP/1.1 \(status) \(statusText)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"

        connection.send(content: response.data(using: .utf8), contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}
