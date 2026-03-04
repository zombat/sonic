# S.O.N.I.C. Call Tracking Feature

## Overview

The call tracking feature has been successfully implemented in S.O.N.I.C. to track INVITE and BYE messages in SIP captures, providing detailed analysis of:

- **Who initiated each call** (sent the INVITE)
- **Who hung up** (sent the BYE or error response) 
- **Disconnect codes and reasons** (BYE, 486 Busy, 487 Request Terminated, etc.)
- **Call patterns and statistics**

## Features Implemented

### 1. Call Session Tracking (`analyzers/call_tracking.py`)
- Tracks complete call sessions by correlating INVITE and BYE messages
- Identifies call initiators and terminators by IP address
- Handles various disconnect scenarios:
  - Normal termination (BYE messages)
  - Error responses (486 Busy, 487 Request Terminated, 480 Unavailable, etc.)
  - Incomplete sessions (missing INVITE or BYE)

### 2. Data Format Conversion (`utils/sip_converter.py`)
- Converts raw SIP text data from scapy into structured JSON format
- Parses SIP headers to extract IP addresses, Call-IDs, and methods
- Handles both tshark JSON output and scapy text output

### 3. Enhanced Data Models (`models/schemas.py`)
- Extended CallFlow model with new tracking fields:
  - `initiator_ip`: IP address of party who sent INVITE
  - `terminator_ip`: IP address of party who sent BYE/error
  - `disconnect_code`: Specific SIP code (BYE, 486, 487, etc.)
  - `hangup_pattern`: "Initiator hung up" or "Recipient hung up"

### 4. Integrated Reporting (`utils/reporting.py`)
- Call tracking analysis integrated into main diagnostic reports
- Graceful fallback when advanced extraction fails
- Detailed statistics and patterns analysis

### 5. Standalone Tool (`call_tracker.py`)
- Independent call tracking tool that works without AI analysis
- Simple tshark-based extraction for reliable operation
- Command-line interface: `python3 call_tracker.py --file capture.pcapng`

## Usage Examples

### In Main S.O.N.I.C. Tool
```bash
python3 sonic.py --file capture.pcapng --model fast
```
The call tracking analysis will appear in the report after the main diagnostic output.

### Standalone Call Tracker
```bash
python3 call_tracker.py --file capture.pcapng
```

## Sample Output

```
================================================================================
📞 CALL INITIATION & TERMINATION TRACKING
================================================================================

📊 CALL STATISTICS:
   • Total calls tracked: 4
   • Complete sessions (INVITE + BYE): 1
   • Incomplete sessions: 3
     ├─ INVITE only (call continues beyond capture): 2
     └─ BYE only (call started before capture): 1
   • Normal terminations (BYE): 2
   • Error terminations: 1

📋 CAPTURE WINDOW ANALYSIS:
   • Calls started in capture: 3
   • Calls ended in capture: 2
   📤 Note: 2 call(s) may still be active beyond capture
   📥 Note: 1 call(s) started before capture began

🏁 HANGUP PATTERNS (Complete Calls Only):
   • Initiator hung up: 0
   • Recipient hung up: 1

🔌 DISCONNECT CODES:
   • BYE: 2 times
   • 487: 1 times

🔍 PATTERNS DETECTED:
   📞 Recipients tend to hang up more often than callers
   ⚠️ More calls end with errors than normal termination
   📤 2 call(s) started during capture but continued beyond
   📥 1 call(s) ended during capture but started before
   📊 Good capture coverage - multiple call events captured

📋 DETAILED CALL SESSIONS:
--------------------------------------------------------------------------------

🆔 Call-ID: dc0d73ed76c66b6@192.0.2.1...
   📤 Partial session - call started in capture, termination outside window
   📞 INVITE: 192.0.2.1 → 192.0.2.2 at 2025-07-15 16:00:00.207861
   ❌ TERMINATED: 487 - Request Terminated
   💭 Context: Call start captured, but termination occurred outside capture window
   ℹ️  This call was initiated during the capture period but may have
      continued beyond the capture window or on different interfaces

🆔 Call-ID: bye-only-789@198.51.100.1...
   📴 Partial session - call termination captured, started before capture
   📞 INVITE: Not captured (call started before capture window)
   📴 BYE: 198.51.100.1 → 198.51.100.2 at 2025-07-15 16:01:30.000000
   💭 Context: Call termination captured, but initiation occurred before capture started
   ℹ️  This call was already in progress when the capture started
      and we only captured its termination
```

## Technical Implementation

### Call Event Detection
- Monitors SIP Methods: INVITE, BYE
- Tracks SIP Response codes: 486, 487, 603, 600, 480, 408, 504
- Correlates events by Call-ID header

### Pattern Analysis
- **Complete Sessions**: Have both INVITE and BYE/error response
- **Incomplete Sessions**: Missing either INVITE or BYE (partial captures)
- **Hangup Patterns**: Determines if initiator or recipient terminated the call
- **Error Analysis**: Categorizes disconnect reasons

### Robustness Features
- Multiple data format support (tshark JSON, scapy text)
- Graceful fallback when advanced extraction fails
- IP address extraction from multiple SIP headers (From, To, Contact, Via)
- Port detection and SIP URI parsing

## Benefits

1. **Call Quality Troubleshooting**: Identify if calls are being terminated unexpectedly
2. **User Behavior Analysis**: See patterns of who typically hangs up first
3. **System Health**: Monitor error response patterns (busy, unavailable, etc.)
4. **Network Diagnostics**: Track call setup and termination across IP endpoints
5. **Capacity Planning**: Understand call patterns and failure rates

## Files Modified/Created

### New Files:
- `analyzers/call_tracking.py` - Core call tracking logic
- `utils/sip_converter.py` - Data format conversion
- `call_tracker.py` - Standalone tracking tool

### Modified Files:
- `models/schemas.py` - Enhanced with call tracking fields
- `utils/reporting.py` - Integrated call tracking into reports
- `extractors/tshark.py` - Added enhanced SIP fields for tracking

## Testing

The implementation has been tested with:
- ✅ Sample synthetic data (known INVITE/BYE patterns)
- ✅ Real PCAP files with SIP traffic (failure.pcapng, MG-SIP-1.pcapng)
- ✅ Error handling for incomplete sessions
- ✅ Multiple disconnect code scenarios (487, 486, etc.)
- ✅ Both complete and incomplete call sessions

## Future Enhancements

Potential improvements could include:
- Call duration calculation (when both INVITE and BYE timestamps are available)
- Multi-party call tracking (conference scenarios)
- Call transfer detection (REFER method tracking)
- Geographic endpoint analysis (if available in capture)
- Historical pattern trending across multiple captures
