# S.O.N.I.C. Architecture

This page shows how the Go implementation of S.O.N.I.C. (`cmd/sonic`, `cmd/sonic-mcp`, and `internal/*`) is structured, including the analysis pipelines, gRPC/TLS decryption sequence, MCP server lifecycle, LLM `ArtifactFactory`, and CI/release workflows.

## 1. Component View (`cmd/*` & `internal/*`)

`cmd/sonic` and `cmd/sonic-mcp` are thin composition roots sharing extractors (`internal/extract`, including the pure-Go PCAP/PCAPNG `go-fast` reader), 22 analyzer packages (`internal/analyze/*`), CI policy gates (`internal/gate`), direct-HTTP LLM clients (`internal/llm`), `ArtifactFactory` (`internal/ai`), guidance renderers (`internal/guide`), secret redaction/audit (`internal/redact`, `internal/wsconfig`), offline HTML5 export (`internal/report`), and the interactive ANSI TUI (`internal/tui`).

```mermaid
flowchart TB
    subgraph Entry["Go Entry Points"]
        CLI["cmd/sonic<br/>CLI Binary (--version, gate, diff, tui)"]
        MCP["cmd/sonic-mcp<br/>MCP JSON-RPC over stdio (--version)"]
    end

    subgraph Guide["Guidance and Registry"]
        MCPSRV["internal/mcpserver<br/>21 tools, 5 prompts, 7 resources"]
        GUIDE["internal/guide<br/>instructions, AST detector meta, --create-skill"]
    end

    subgraph AI["Direct-HTTP LLM Layer"]
        ORCH["internal/ai<br/>ArtifactFactory + ResponseAdapters"]
        LLM["internal/llm<br/>Provider / Completer over net/http<br/>ollama, anthropic, openai, azure"]
    end

    subgraph Core["Extractors, CI Gate & 22 Analyzers"]
        EXT["internal/extract<br/>SIP, network, dataplane, pcap_fastpath, http2,<br/>http_messages, tls_secrets, snmp, aaa, esp, auth_info"]
        ANA["internal/analyze/*<br/>netorch, diff, 20 protocol/VPN/SIP packages"]
        SEC["internal/wsconfig + internal/redact + internal/gate<br/>/dev/shm tmpfs keys, audit redaction, CI gate"]
    end

    subgraph Report["Reporting, TUI and Process Safety"]
        REP["internal/report + internal/tui<br/>Markdown, HTML5, JSON, TUI, stdio fd guard"]
        TSH[("tshark")]
    end

    CLI --> ANA & ORCH & GUIDE & REP
    MCP --> MCPSRV --> GUIDE & ANA & ORCH
    ORCH --> EXT & ANA & LLM
    ANA --> EXT --> SEC --> TSH
    MCP --> REP
```

## 2. Sequence: gRPC and TLS Decryption

Deterministic, no LLM, powered by Wireshark HTTP/2, HPACK, gRPC, TLS, and protobuf dissectors via `tshark`.

```mermaid
sequenceDiagram
    autonumber
    participant U as sonic / sonic-mcp
    participant G as analyze/grpc
    participant H as extract/http2
    participant S as extract/tls_secrets
    participant T as tshark
    participant R as internal/report & redact

    U->>G: file, keylog, ports, protos
    G->>H: DiscoverTCPConnections & FindPrefaces
    H->>T: -T fields (SYN, RST, TLS ClientHello/ServerHello)
    T-->>H: connection list + Decode-As plan
    alt keylog file or pcapng DSB present
        G->>S: InspectKeyLog / InspectPcapngSecrets
        S-->>G: labels & client randoms (no secret bytes retained)
    end
    G->>H: StreamHTTP2Packets(decode_as, keylog)
    H->>T: tshark -T pdml (streamed)
    loop each HTTP/2 frame
        T-->>H: PDML packet
        H-->>G: headers, HTTP/2 frames, protobuf fields
        G->>G: reassemble gRPC RPCs, decode gNMI, mask credentials
    end
    G-->>U: GrpcReport
    U->>R: redacted JSON / Markdown / console summary
```

## 3. Sequence: MCP Tool Call & Stdio Isolation

Before entering the JSON-RPC loop, `cmd/sonic-mcp` duplicates descriptor `1` for protocol output and redirects OS `stdout` to `stderr` (`internal/report` `ReserveStdoutForProtocol`) so diagnostic progress never corrupts JSON-RPC framing.

```mermaid
sequenceDiagram
    autonumber
    participant A as MCP Client
    participant S as cmd/sonic-mcp (ReserveStdout)
    participant M as internal/mcpserver
    participant O as internal/analyze/* / ai
    participant R as internal/redact

    A->>S: initialize / tools/list / tools/call
    S->>M: dispatch request on reserved FD
    M->>O: decode args & run analyzer / LLM workflow
    O-->>M: typed report struct (JSON)
    M->>R: RedactText(reportJSON)
    R-->>M: secret-scrubbed JSON + structuredContent
    M-->>A: newline-delimited JSON-RPC 2.0 response
```

## 4. Sequence: SIP Analysis with an LLM

In Go (`internal/ai` + `internal/llm`), SIP and RTP extraction feed deterministic scoring alongside direct-HTTP SSE/NDJSON calls through `llm.Completer`, normalized and redacted via `ArtifactFactory` before Markdown/JSON output.

```mermaid
sequenceDiagram
    autonumber
    participant U as CLI or MCP client
    participant O as ai.RunAnalysisMode / orchestrator
    participant X as internal/extract (tshark)
    participant C as internal/analyze/sip (quality & MOS)
    participant L as llm.Completer (direct net/http)
    participant F as ai.ArtifactFactory (ResponseAdapters)
    participant R as internal/report & redact

    U->>O: --file, --model, --quality, --mos
    O->>X: ExtractSIPData + ExtractAuthAndRegistrationInfo
    X-->>O: SIP messages, SDP, RTP stats
    O->>C: ScoreCallQuality + AnalyzeRTPStreamsFromSummary
    C-->>O: CallQuality, MOSAnalysis
    O->>L: Complete(fast / detailed / deep / combined)
    L-->>O: raw completion (redacted)
    O->>F: BuildDiagnostic (Validate + Redact)
    F-->>O: DiagnosticArtifact
    O->>R: Markdown, JSON, or console summary
```

## 5. Typed Packet & Report Model (`internal/model`)

Every dissector, analyzer, and reporter communicates through explicit domain structs rather than untyped dictionaries:
- **Normalized Frame Records (`Record`)**: typed pointers and presence flags (`*int`, `*bool`, `netip.Addr`, `TCPHeader`, `UDPHeader`, `IKEHeader`, `ESPHeader`, `NHRPPacket`, `BGPMessage`, `OSPFHeader`, `EIGRPHeader`) ensure zero values never mask absent `tshark` fields.
- **Deterministic Reports**: `DetectorReport`, `NetworkReport`, `AuditReport`, `GrpcReport`, `HTTPReport`, `SNMPReport`, `AAAReport`, `ESPReport`, `CorrelateReport`, `TimelineReport`, `DiffReport`, and `GateReport` serialize directly to stable JSON schemas (`testdata/golden/` for parity fixtures).
- **AI Artifacts**: `ReportOutput`, `CallDiagnostic`, `AudioQualityDiagnostic`, `CallFlow`, and `PartialStreamingResult` enforce schema invariants inside `ArtifactFactory`.

## 6. CI & Release Pipelines

`.github/workflows/ci.yml` and `.github/workflows/release.yml` enforce Go quality checks and cross-compile signed archives on every change and version tag:

```mermaid
flowchart LR
    PUSH["push / pull_request"] --> CI["ci.yml: go job"]
    TAG["push tag v*"] --> REL["release.yml: release job"]

    subgraph CI["ci.yml (Ubuntu + tshark)"]
        C1["gofmt + 6-target cross go vet"] --> C2["make test (-race + cover)"]
        C2 --> C3["make fuzz (20 fuzz targets)"]
        C3 --> C4["make build release"]
    end

    subgraph REL["release.yml (v* tags)"]
        R1["make vet test fuzz"] --> R2["make release VERSION=tag"]
        R2 --> R3["GitHub Release: .tar.gz / .zip + SHA256SUMS"]
    end
```
