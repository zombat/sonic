# Subject-Void Triad (Trifecta) Project Rule

Always use all three Triad MCP servers (`trifecta_groundconfig`, `trifecta_vuln-corpus`, `trifecta_argus`) when working in `/home/noot/sonic`, and ensure they learn as we go.

## Required Workflow (6-Step Continuous Verification Loop)

1. **Find**:
   - Run `trifecta_vuln-corpus.run_sweep` (`target: "/home/noot/sonic"`, or `diff_base` for branch/PR diffs) and `trifecta_argus.map_surface` on modified/new modules.
   - Query `trifecta_groundconfig.query_knowledge_by_domain` (e.g., `telephony_voice`, `wan_routing`, `datacenter_fabric`, `verification_assert`, `ci_toolchains`) when implementing or debugging protocol detectors, SIP/RTP, IPsec/DMVPN/BGP/OSPF/EIGRP, gRPC/TLS, or PCAP handling.
2. **Prove**:
   - For suspect parsers, `tshark`/PDML extractors, or MCP input boundaries, use `trifecta_argus.expand_seeds` / `synthesize_reproducer` / `verify_invariant` or `trifecta_vuln-corpus.generate_repro`.
3. **Stage (Quarantine)**:
   - Stage newly discovered code weaknesses via `trifecta_vuln-corpus.submit_finding` or `trifecta_argus.draft_lead`.
   - Stage newly discovered protocol/PCAP/network edge cases via `trifecta_groundconfig.ingest_knowledge`.
4. **Fix**:
   - Consult `trifecta_vuln-corpus.get_codeguard_rules` for defensive coding patterns when remediating issues.
5. **Validate**:
   - Re-run `trifecta_vuln-corpus.run_sweep` / `verify_fix` and `/home/noot/sonic/venv/bin/python -m pytest -q`.
6. **Store (Learn As We Go)**:
   - Promote verified findings/leads/knowledge with `trifecta_vuln-corpus.vet_finding`, `trifecta_argus.vet_lead`, and `trifecta_groundconfig.vet_knowledge` so all three corpora retain `sonic` lessons permanently.
