# S.O.N.I.C. Architecture

This page shows how S.O.N.I.C. is put together: the components, the three analysis paths, the main classes and the CI pipeline. The diagrams are Mermaid, so GitHub renders them in place.

Every name here is a real module or function in the repository. Read the code for the details.

## 1. Component view

Two entry points, the CLI (`sonic.py`) and the MCP server (`mcp_server.py`), call the same orchestrators. The orchestrators drive the extractors, which are the only code that talks to tshark or scapy. Analyzers turn records into findings. The reporting layer writes what the user sees.

```mermaid
flowchart TB
    subgraph Entry["Entry points"]
        CLI["sonic.py<br/>CLI"]
        MCP["mcp_server.py<br/>FastMCP over stdio"]
    end

    subgraph Orch["Orchestrators"]
        ORCH["analyzers/orchestrator.py<br/>run_analysis_mode (SIP + LLM)"]
        NET["analyzers/network_orchestrator.py<br/>analyze_network_capture and friends"]
        GRPC["analyzers/grpc_inspect.py<br/>analyze_grpc_capture"]
    end

    subgraph Extract["Extractors"]
        TS["extractors/tshark.py<br/>SIP via tshark"]
        SCAPY["read_pcap_with_scapy<br/>fallback"]
        NETX["extractors/network.py<br/>control plane"]
        DP["extractors/dataplane.py<br/>data plane"]
        H2["extractors/http2.py<br/>discover, decode-as, PDML"]
        SEC["extractors/tls_secrets.py<br/>key log and pcapng DSB"]
        AUTH["extractors/auth_info.py"]
    end

    subgraph Analyze["Analyzers"]
        SIPA["call_tracking, call_quality_scoring,<br/>rtp_mos_analysis, handlers/sip"]
        DET["Network detectors<br/>ipsec_vpn, gre_nhrp, dmvpn_phase3,<br/>routing_health, reachability, convergence,<br/>cleartext_audit, tls_inspect,<br/>path_mtu, esp_overhead, tcp_health, qos,<br/>correlate, timeline"]
        GNMI["analyzers/gnmi_decode.py<br/>protobuf without .proto"]
    end

    subgraph AI["LLM layer (optional)"]
        AIMOD["ai/*<br/>analysis, streaming, batch"]
        LLMC["llm_config.py"]
        PROV["ollama / anthropic / openai<br/>via DSPy"]
    end

    subgraph Report["Reporting"]
        RSIP["utils/reporting.py<br/>SIP markdown and console"]
        RNET["utils/network_reporting.py<br/>JSON and markdown"]
        RGRPC["utils/grpc_reporting.py<br/>summary, markdown, JSON"]
    end

    subgraph Ext["External tools"]
        TSHARK[("tshark (3.6 tested)")]
        SCAPYLIB[("scapy")]
    end

    CLI --> ORCH & NET & GRPC
    MCP --> ORCH & NET & GRPC

    ORCH --> TS
    TS -. "fails" .-> SCAPY
    ORCH --> SIPA --> AIMOD --> LLMC --> PROV
    ORCH --> RSIP

    NET --> NETX & DP
    NET --> DET --> RNET
    DET --> AUTH

    GRPC --> H2 & SEC
    GRPC --> GNMI
    GRPC --> RGRPC

    TS --> TSHARK
    NETX --> TSHARK
    DP --> TSHARK
    H2 --> TSHARK
    SCAPY --> SCAPYLIB
    NETX -. "scapy backend" .-> SCAPYLIB
    DP -. "scapy backend" .-> SCAPYLIB
```

The MCP server supplies a separate guide: instructions, prompts and `sonic://guide/*` resources, all built by `utils/agent_guide.py`. `utils/protocol_stdout.py` keeps stdout for JSON-RPC only.

## 2. Sequence: gRPC and TLS decryption

This is the most involved path. It runs with no LLM, and it needs tshark.

```mermaid
sequenceDiagram
    autonumber
    participant U as CLI or MCP client
    participant G as grpc_inspect.analyze_grpc_capture
    participant H as extractors/http2
    participant S as extractors/tls_secrets
    participant T as tshark
    participant D as grpc_inspect (_Conn, _Rpc, _Framer)
    participant N as gnmi_decode
    participant R as utils/grpc_reporting

    U->>G: file, keylog_file, ports, protos
    G->>H: discover(file, ports)
    H->>T: -T fields: SYN, SYN-ACK, RST, TLS hellos
    T-->>H: TcpConnection per stream
    G->>H: find_prefaces(file)
    H->>T: HTTP/2 connection prefaces
    G->>H: plan_decode_as(conns)
    H-->>G: -d tcp.port==P,http2 or ,tls
    alt key log or pcapng secrets given
        G->>S: key_log_labels or pcapng_secrets
        S-->>G: labels and client randoms only, no secret values kept
    end
    G->>H: tls_decryption(file, decode_as, keylog)
    H->>T: decrypt with the secrets
    H-->>G: per session: decrypted?, source, reason
    G->>H: iter_http2_packets(file, decode_as, keylog)
    H->>T: tshark -T pdml (streamed)
    loop each HTTP/2 frame
        T-->>H: PDML packet
        H-->>D: frame, headers, protobuf fields
        D->>D: reassemble gRPC messages, mask credentials
    end
    D->>N: decode_request / decode_response
    N-->>D: paths, values, notifications
    D-->>G: GrpcAnalysis
    G->>R: summary, markdown, JSON
    R-->>U: console, .grpc.md, or JSON
```

## 3. Sequence: MCP tool call

An agent calls a tool over stdio. The tool runs the same orchestrator code as the CLI, so both paths return the same results.

```mermaid
sequenceDiagram
    autonumber
    participant A as MCP client (agent)
    participant M as mcp_server (FastMCP)
    participant P as utils/protocol_stdout
    participant O as orchestrator (SIP, network, gRPC)
    participant E as extractors and analyzers

    A->>M: tools/call analyze_network_pcap
    M->>M: map arguments onto the orchestrator's parameters
    M->>O: analyze_network_capture(...)
    O->>E: extract records
    E-->>O: findings
    O-->>M: JSON-safe result (to_jsonable)
    M->>P: write JSON-RPC response to stdout
    P-->>A: result (verdict, findings, limits)
```

`protocol_stdout` exists so that a stray `print` cannot corrupt the protocol stream. Logs go to stderr.

## 4. Sequence: SIP analysis with an LLM

```mermaid
sequenceDiagram
    autonumber
    participant U as CLI
    participant O as analyzers/orchestrator.run_analysis_mode
    participant X as extractors/tshark (scapy fallback)
    participant C as call_tracking and call_quality_scoring
    participant L as ai/* (DSPy)
    participant V as llm_config provider
    participant R as utils/reporting

    U->>O: --file, --model, --quality
    O->>X: extract_sip_data(file)
    X-->>O: SIP messages, RTP stats
    O->>C: track calls, score quality, MOS
    C-->>O: CallDiagnostic, AudioQualityDiagnostic
    O->>L: analyze(fast / detailed / combined)
    L->>V: prompt (fast model JSON, then detailed text)
    V-->>L: completion
    L-->>O: structured result and narrative
    O->>R: markdown or console report
```

## 5. Class view

### gRPC analysis

The gRPC analyzer keeps per-connection state in three small classes, and the orchestrating class collects them.

```mermaid
classDiagram
    class GrpcAnalysis {
        +disc
        +conns: Dict~int, _Conn~
        +packets
        +start, end
        +secrets_source
        +conn_for(packet)
    }
    class _Conn {
        +index
        +client, server
        +rpcs: Dict~int, _Rpc~
        +rst_streams, goaways
        +pings, stalls
        +credentials
        +metadata_keys
        +hpack_failures
        +tls_seen
    }
    class _Rpc {
        +conn
        +stream_id
        +request_headers, response_headers
        +trailers
        +reset
        +client_ended, server_ended
        +framers: client and server
        +protobuf
    }
    class _Framer {
        +buf
        +messages
        +count, total, max
        +lost, skip
    }
    class TcpConnection {
        +index
        +a, b
        +client, server
        +server_known_by
        +preface_frame
        +tls_client_hello, tls_server_hello
        +sni, alpn
        +resets
    }
    class Http2Extraction {
        +secret_values
        +identity_values
        +status
        +packets: iterator
    }

    GrpcAnalysis "1" *-- "many" _Conn : conns
    _Conn "1" *-- "many" _Rpc : rpcs
    _Rpc "1" *-- "2" _Framer : framers
    GrpcAnalysis ..> TcpConnection : built from discover()
    GrpcAnalysis ..> Http2Extraction : fed by iter_http2_packets()
```

Attributes are the ones that matter for reading the code, and `analyzers/grpc_inspect.py` (lines 220 to 420) and `extractors/http2.py` (lines 148 to 170, 400 to 415) are the reference.

### Pydantic schemas (SIP path)

`SipDiagnosticReport` holds the calls. `AuthenticationMetrics` stands alone and is built by the auth extractor, not nested in the report.

```mermaid
classDiagram
    class SipDiagnosticReport {
        +total_calls_analyzed
        +calls
        +overall_assessment
        +recommendations
    }
    class CallDiagnostic {
        +call_id
        +caller_ip, callee_ip
        +user_agents
        +audio_quality
        +network_baseline
        +call_flow
        +diagnostic_summary
    }
    class CallFlow {
        +call_setup_method
        +call_termination
        +response_codes
        +initiator_ip, terminator_ip
        +disconnect_code
        +hangup_pattern
    }
    class AudioQualityDiagnostic {
        +codec_used
        +payload_types
        +rtp_port
        +potential_issues
    }
    class AuthenticationMetrics {
        +total_challenges
        +register_attempts, register_successes
        +unique_realms
        +weak_algorithms
        +authentication_anomalies
    }

    SipDiagnosticReport "1" *-- "many" CallDiagnostic : calls
    CallDiagnostic "1" *-- "1" CallFlow : call_flow
    CallDiagnostic "1" *-- "1" AudioQualityDiagnostic : audio_quality
```

`AuthenticationMetrics` is not in the diagram's containment, because `SipDiagnosticReport` does not reference it.

## 6. CI pipeline

This is the workflow in `.github/workflows/ci.yml`. The lint job reports but does not yet fail the build, because the existing code does not yet pass black or flake8.

```mermaid
flowchart LR
    PUSH["push or pull_request"] --> TEST
    PUSH --> LINT
    PUSH --> FIX
    PUSH --> SEC

    subgraph TEST["test job (matrix 3.10 to 3.13)"]
        T1["apt install tshark"] --> T2["pip install -r requirements.txt -r requirements-dev.txt"]
        T2 --> T3["pytest -q --cov"]
        T3 --> T4["upload coverage.xml"]
    end

    subgraph LINT["lint job (non-blocking)"]
        L1["black --check"] --> L2["flake8"]
    end

    subgraph FIX["fixture job"]
        F1["generate fixtures"] --> F2{"git diff clean?"}
        F2 -- "no" --> F3["fail: fixtures not reproducible"]
        F2 -- "yes" --> F4["ok"]
    end

    subgraph SEC["security jobs"]
        S1["CodeQL"]
        S2["pip-audit (non-blocking)"]
    end
```
