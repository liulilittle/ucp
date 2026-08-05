# UCP C++ Documentation Overview

[Chinese](README_CN.md)

This document provides navigation to the complete documentation suite for the UCP (Universal Communication Protocol) C++ implementation. UCP is a pure control protocol: CID round-robin switching, FEC forward error correction, and SACK/NAK recovery all feed delivery samples into the KCC congestion control for accurate bandwidth/delay estimation.

## Document List

| Document | Description |
|---|---|
| [index_EN.md](index_EN.md) | Full document index, core concepts quick reference, source file listing |
| [architecture_EN.md](architecture_EN.md) | Six-layer runtime architecture, UcpPcb protocol control block, Worker Thread serial model |
| [protocol_EN.md](protocol_EN.md) | Wire format specification, 8 packet types, Flags bit layout, state machine |
| [api_EN.md](api_EN.md) | Public API reference, UcpConfiguration/UcpServer/UcpConnection |
| [performance_EN.md](performance_EN.md) | Congestion control, benchmark results |
| [constants_EN.md](constants_EN.md) | All protocol constants organized by subsystem |

## Quick Navigation

| Goal | Document |
|---|---|
| Learn layered architecture and threading model | [architecture_EN.md](architecture_EN.md) |
| View packet format and codec specification | [protocol_EN.md](protocol_EN.md) |
| Write applications using UCP | [api_EN.md](api_EN.md) |
| Tune KCC congestion control parameters and performance | [performance_EN.md](performance_EN.md) |
| Look up constant defaults and meanings | [constants_EN.md](constants_EN.md) |

## Related Documents

- [Project Root README](../README_EN.md) — C++ implementation overview
- [Linux Kernel Module](../../linux/README.md) — KCC Geodesic Congestion Control module (tcp_kcc.c v2.0, with KCC Forwarding (KF) for cross-connection bandwidth sharing)

## Documentation Conventions

All documents follow these conventions:

- Multi-byte integers use network byte order (big-endian)
- Time values are in microseconds
- Sizes are in bytes
- Constant names use UPPER_CASE (protocol constants) or kCamelCase (UCP internal constants)

---

## License and Trademark

MIT License. See [LICENSE](../../LICENSE) for full text.

Copyright (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ is a trademark of PPP PRIVATE NETWORK.
