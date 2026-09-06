<div align="center">

# Low-Level Research

**Vulnerability discovery in C libraries, kernel modules, and systems software**

<sub>Manual source code auditing | Coverage-guided fuzzing | Exploit development</sub>

---

[![Research](https://img.shields.io/badge/Methodology-Source_Audit_+_Fuzzing-0d1117?style=for-the-badge)]()
[![Findings](https://img.shields.io/badge/Findings-17_Vulnerabilities-d32f2f?style=for-the-badge)]()
[![CWEs](https://img.shields.io/badge/CWE_Classes-12_Distinct-f57c00?style=for-the-badge)]()

</div>

---

## Research Portfolio

Original vulnerability research against real-world C codebases. Each finding includes vulnerable source code, a working proof-of-concept, root cause analysis, and remediation guidance.

| Target | Domain | Method | Findings | Severity | Writeup |
|--------|--------|--------|----------|----------|---------|
| **Parson v1.5.3** | C JSON parser (2,487 LOC) | Manual source audit | 14 vulnerabilities, 9 CWE classes | 4 HIGH / 7 MEDIUM / 3 LOW | [Full Report](vulnerabilities/parson/) |
| **Fastsocket** | Linux kernel socket library (SINA Corp) | AFL++ fuzzing + ASan | 3 vulnerabilities, 24 crash inputs | 1 CRITICAL / 2 HIGH | [Full Report](vulnerabilities/fastsocket/) |

---

## Parson v1.5.3 -- 14 Vulnerabilities in a C JSON Parser

**Target:** [parson.c](https://github.com/kgabis/parson) -- lightweight single-file JSON library
**Method:** Manual source code audit of all 2,487 lines
**Date:** September 2026

### Attack Surface

```mermaid
graph TD
    subgraph "Public API Entry Points"
        PARSE["json_parse_string()<br/>json_parse_file()"]
        SERIAL["json_serialize_to_string()"]
        BUILD["json_value_init_*()<br/>json_object_set_*()"]
        CONFIG["json_set_float_serialization_format()<br/>json_set_number_serialization_function()"]
        OPS["json_value_deep_copy()<br/>json_validate()<br/>json_value_equals()"]
    end

    PARSE --> UTF8["is_valid_utf8()"]
    PARSE --> HASH["hash_string() djb2"]
    PARSE --> NUM["strtod()"]
    SERIAL --> SPRINTF["parson_sprintf()<br/>vsprintf wrapper"]
    SERIAL --> RECURSE["json_serialize_to_buffer_r()"]
    BUILD --> OPS
    CONFIG --> GLOBALS["Global mutable state<br/>no synchronization"]

    UTF8 -->|"#2 reads 3 bytes OOB"| V2["Heap Over-Read<br/>CWE-125"]
    HASH -->|"#9 deterministic collisions"| V9["HashDoS 288x<br/>CWE-407"]
    NUM -->|"#10 locale-dependent"| V10["Data Corruption<br/>CWE-474"]
    SPRINTF -->|"#1 no bounds on vsprintf"| V1["Stack Overflow<br/>CWE-120"]
    RECURSE -->|"#3 int wraps at 2GB"| V3["Integer Overflow<br/>CWE-190"]
    RECURSE -->|"#5-8 no depth limit"| V5["Stack Exhaustion<br/>CWE-674"]
    GLOBALS -->|"#4 free while reading"| V4["Use-After-Free<br/>CWE-416"]
    CONFIG -->|"#11 no buf size param"| V11["Callback Overflow<br/>CWE-120"]

    style V1 fill:#333,color:#fff,stroke:#fff
    style V2 fill:#333,color:#fff,stroke:#fff
    style V3 fill:#333,color:#fff,stroke:#fff
    style V4 fill:#333,color:#fff,stroke:#fff
    style V5 fill:#555,color:#fff,stroke:#ccc
    style V9 fill:#555,color:#fff,stroke:#ccc
    style V10 fill:#555,color:#fff,stroke:#ccc
    style V11 fill:#555,color:#fff,stroke:#ccc
```

### How Each Vulnerability Works

```mermaid
sequenceDiagram
    participant A as Attacker
    participant P as Parson
    participant M as Memory

    Note over A,M: #1 Stack Buffer Overflow (HIGH)
    A->>P: Set format "%.2000f"
    A->>P: Serialize DBL_MAX
    P->>M: vsprintf writes 2,311 bytes into 64-byte stack buf
    M-->>M: Return address overwritten

    Note over A,M: #2 Heap Over-Read (HIGH)
    A->>P: 1-byte string with 0xF4 lead
    P->>M: verify_utf8_sequence reads buf[1..3] OOB
    M-->>A: Leaks adjacent heap data (Heartbleed-class)

    Note over A,M: #3 Integer Overflow (HIGH)
    A->>P: JSON tree >2 GB serialized
    P->>P: int accumulator wraps to small value
    P->>M: malloc(small) then write >2 GB into it

    Note over A,M: #4 Thread Race / UAF (HIGH)
    A->>P: Thread 1 serializes (reads format ptr)
    A->>P: Thread 2 changes format (frees old ptr)
    P->>M: Thread 1 dereferences freed memory

    Note over A,M: #9 HashDoS (MEDIUM)
    A->>P: 8,192 keys with identical djb2 hashes
    P->>P: Every insertion is O(n) linear scan
    Note over P: 288x slowdown (608ms vs 2.1ms)
```

### Findings Table

| # | Vulnerability | CWE | Impact |
|---|--------------|-----|--------|
| 1 | Stack overflow via `vsprintf` -- no bounds on format output | CWE-120/676 | RCE |
| 2 | Heap over-read in UTF-8 -- reads 3 bytes past allocation | CWE-125 | Info leak |
| 3 | Integer overflow in serialization size -- `int` wraps at 2 GB | CWE-190/122 | Heap overflow |
| 4 | Thread-unsafe globals -- UAF on `parson_float_format` | CWE-362/416 | Corruption |
| 5-8 | Uncontrolled recursion in 4 post-parse functions | CWE-674 | DoS |
| 9 | HashDoS via deterministic djb2 collisions | CWE-407 | DoS |
| 10 | Locale confusion -- `strtod` uses `,` as decimal in some locales | CWE-474 | Data corruption |
| 11 | Callback API gives buffer pointer with no size | CWE-120 | Stack overflow |
| 12-14 | Int truncation, alloc overflow, TOCTOU | CWE-190/367 | Theoretical |

---

## Fastsocket -- 3 Memory Corruption Vulnerabilities in a Kernel Socket Library

**Target:** [fastsocket](https://github.com/fastos/fastsocket) -- SINA Corporation's kernel module + userspace library
**Method:** Coverage-guided fuzzing with AFL++ 5.03c, confirmed via ASan + UBSan
**Date:** September 2026

### Architecture and Attack Surface

```mermaid
graph TB
    subgraph "Userspace"
        APP["Application<br/>(Nginx, HAProxy)"]
        LIB["libsocket.so<br/>LD_PRELOAD"]
        DEMO["demo/server.c<br/>HTTP server"]
    end

    subgraph "Kernel"
        MOD["/dev/fastsocket<br/>kernel module"]
    end

    APP -->|"socket() listen() close()"| LIB
    LIB -->|"ioctl()"| MOD
    DEMO --> LIB

    LIB -.->|"fd indexes array<br/>with no bounds check"| V1["VULN-01: Heap OOB<br/>fsocket_fd_set[fd]<br/>CRITICAL"]
    DEMO -.->|"strncpy fills buffer<br/>without null terminator"| V2["VULN-02: Stack Overflow<br/>argument parsing<br/>HIGH"]
    DEMO -.->|"double-free corrupts<br/>freelist into cycle"| V3["VULN-03: UAF / Double-Free<br/>pool allocator<br/>HIGH"]

    style V1 fill:#333,color:#fff,stroke:#fff
    style V2 fill:#555,color:#fff,stroke:#ccc
    style V3 fill:#555,color:#fff,stroke:#ccc
    style LIB fill:#222,color:#fff,stroke:#888
    style MOD fill:#222,color:#fff,stroke:#888
```

### How Each Vulnerability Works

```mermaid
sequenceDiagram
    participant K as Kernel
    participant L as libsocket.so
    participant H as Heap

    Note over K,H: VULN-01: Heap Buffer Overflow (CRITICAL)
    K->>L: accept() returns fd=70000
    L->>L: close(70000)
    L->>H: fsocket_fd_set[70000] -- 17,856 bytes past allocation
    H-->>H: Adjacent heap object corrupted

    Note over K,H: VULN-02: Stack Buffer Overflow (HIGH)
    K->>L: argv[2] = 64+ bytes
    L->>L: strncpy(log_path, argv[2], 64) -- no null terminator
    L->>L: strlen(log_path) reads past buffer
    L-->>L: Stack redzone hit

    Note over K,H: VULN-03: Double-Free / UAF (HIGH)
    L->>H: free_context(ctx1) -- legitimate
    L->>H: free_context(ctx1) -- DOUBLE FREE
    Note over H: Freelist: ctx1->ctx1->ctx1... (cycle)
    L->>H: alloc_context() returns ctx1
    L->>H: alloc_context() returns ctx1 AGAIN
    Note over H: Two connections share one buffer
```

### Fuzzing Results

| Harness | Target | Crashes | Coverage | Verdict |
|---------|--------|---------|----------|---------|
| `fuzz_fdset` | `libsocket.c` -- fd_set array | **8** | 38.89% | **CRITICAL** |
| `fuzz_argparse` | `server.c` -- strncpy/strlen | **11** | 38.98% | **HIGH** |
| `fuzz_context_pool` | `server.c` -- slab allocator | **5** | 25.53% | **HIGH** |
| `fuzz_http_parse` | `server.c` -- HTTP pipeline | 0 | 20.00% | CLEAN |

---

## Books and Resources

| Resource | Description |
|----------|------------|
| [The Art of Exploit Development](books/The_Art_of_Exploit_Development.pdf) | 222-page guide covering the full exploit development pipeline -- from x86/x64 architecture fundamentals through stack and heap exploitation to kernel exploits and fuzzing. |

<details>
<summary>Book Contents</summary>

- **Part I -- Foundations:** Computer architecture, x86/x64 assembly, memory layout, C for exploit devs
- **Part II -- Stack-Based Exploitation:** Buffer overflows, controlling EIP/RIP, shellcode, encoding/evasion, SEH exploits
- **Part III -- Bypassing Protections:** Stack canaries, DEP/NX + ROP, ASLR bypass, PIE/RELRO/FORTIFY_SOURCE
- **Part IV -- Heap Exploitation:** malloc internals, heap overflow, UAF, double free, tcache, heap feng shui
- **Part V -- Format Strings and Integer Bugs:** Format string vulnerabilities, integer overflow/signedness
- **Part VI -- Advanced Topics:** Kernel exploitation, race conditions/TOCTOU, type confusion, sandbox escape, browser exploitation
- **Part VII -- Practical Application:** Fuzzing, pwntools workflows, CTF walkthroughs, real-world case studies, responsible disclosure

</details>

---

## Research Methodology

```mermaid
graph LR
    A["1. Select Target<br/>Real-world C code<br/>processing untrusted input"] --> B["2. Map Attack Surface<br/>Public API functions<br/>I/O boundaries"]
    B --> C["3. Find Candidates<br/>Dangerous functions<br/>Missing bounds checks"]
    C --> D["4. Trace Data Flow<br/>Attacker-reachable?<br/>Security-relevant outcome?"]
    D --> E["5. Prove It<br/>Write PoC<br/>Observable failure"]
    E --> F["6. Classify + Report<br/>CWE mapping<br/>Severity + remediation"]

    style A fill:#1a1a1a,color:#fff,stroke:#555
    style B fill:#2a2a2a,color:#fff,stroke:#555
    style C fill:#3a3a3a,color:#fff,stroke:#666
    style D fill:#4a4a4a,color:#fff,stroke:#666
    style E fill:#555,color:#fff,stroke:#777
    style F fill:#666,color:#fff,stroke:#888
```
