# Low-Level Research

Collection of low-level security research — vulnerability discovery in C libraries, kernel modules, and binary exploitation techniques.

## Vulnerability Research

| Target | Type | Findings | Severity |
|---|---|---|---|
| [Parson](vulnerabilities/parson/) | C JSON library | 15+ vulns: stack/heap overflow, UAF, TOCTOU, HashDoS, uncontrolled recursion | Critical |
| [Fastsocket](vulnerabilities/fastsocket/) | Linux kernel module | 3 vulns: heap BOF, stack BOF, UAF in pool allocator | Critical |

### Parson (C Library)

Lightweight JSON parser used across embedded and server applications. Audit uncovered memory corruption bugs in the serializer and parser, thread-safety violations in global state, algorithmic complexity attacks via predictable hashing, and TOCTOU issues in the two-pass serialization model.

**Key findings:** Stack buffer overflow in `json_sprintf`, heap over-read in UTF-8 validation, integer overflow in serialization, HashDoS via deterministic djb2 collisions, 4 vectors for uncontrolled recursion.

### Fastsocket (Kernel Module)

High-performance socket optimization module for Linux. Three critical kernel-level vulnerabilities enable privilege escalation from userspace: heap buffer overflow in fd set management, stack buffer overflow in argument parsing, and use-after-free in the connection pool allocator.

## Books & Resources

| Resource | Description |
|---|---|
| [The Art of Exploit Development](books/The_Art_of_Exploit_Development.pdf) | 222-page guide covering x86/x64 architecture, buffer overflows, ROP chains, heap exploitation, shellcode, kernel exploits, format strings, race conditions, fuzzing, and pwntools workflows. From foundations to advanced techniques. |

### Book Contents

- **Part I — Foundations:** Computer architecture, x86/x64 assembly, memory layout, C for exploit devs
- **Part II — Stack-Based Exploitation:** Buffer overflows, controlling EIP/RIP, shellcode, encoding/evasion, SEH exploits
- **Part III — Bypassing Protections:** Stack canaries, DEP/NX + ROP, ASLR bypass, PIE/RELRO/FORTIFY_SOURCE
- **Part IV — Heap Exploitation:** malloc internals, heap overflow, UAF, double free, tcache, heap feng shui
- **Part V — Format Strings & Integer Bugs:** Format string vulnerabilities, integer overflow/signedness
- **Part VI — Advanced Topics:** Kernel exploitation, race conditions/TOCTOU, type confusion, sandbox escape, browser exploitation
- **Part VII — Practical Application:** Fuzzing, pwntools workflows, CTF walkthroughs, real-world case studies, responsible disclosure

## Author

**Nour Issa** ([@KazamaDono](https://github.com/KazamaDono))
- [spectra-vrg.org](https://spectra-vrg.org)
- [LinkedIn](https://linkedin.com/in/ayukotsu)
