# Parson — C JSON Library Vulnerability Research

**Target:** [Parson](https://github.com/kgabis/parson) (lightweight JSON library in C)  
**Findings:** 15+ vulnerabilities across multiple vulnerability classes  
**Severity:** Critical / High  

## Overview

Parson is a widely-used single-file C JSON parser. Audit revealed 15+ vulnerabilities spanning memory corruption, thread safety, algorithmic complexity, and time-of-check-to-time-of-use issues.

## Vulnerabilities

### Memory Corruption

| ID | Type | Location | Impact |
|---|---|---|---|
| PSN-001 | Stack buffer overflow | `json_sprintf()` | Code execution via oversized format output |
| PSN-002 | Heap over-read | UTF-8 validation path | Information leak from adjacent heap memory |
| PSN-003 | Integer overflow | Serialization length calculation | Undersized allocation leading to heap overflow |

### Use-After-Free / Thread Safety

| ID | Type | Location | Impact |
|---|---|---|---|
| PSN-004 | Use-after-free | Global allocator state | Dangling pointer dereference in multi-threaded use |
| PSN-005 | Thread-unsafe globals | `json_set_allocation_functions()` | Race condition on global function pointers |

### Logic / Design

| ID | Type | Location | Impact |
|---|---|---|---|
| PSN-006 | TOCTOU | Serialize size/write pass | Size calculated in first pass, buffer written in second — intervening mutation causes overflow |
| PSN-007 | HashDoS | djb2 hash function | Deterministic hash collisions degrade O(1) lookups to O(n), causing algorithmic DoS |
| PSN-008–011 | Uncontrolled recursion | 4 vectors in parser | Stack exhaustion via deeply nested JSON (arrays, objects, mixed nesting, value recursion) |

## Technical Details

### Stack Buffer Overflow in `json_sprintf`

The `json_sprintf` function writes formatted output to a fixed-size stack buffer without bounds checking. A JSON value with a sufficiently long string representation overwrites the return address.

### Heap Over-Read in UTF-8 Validation

The UTF-8 validation routine reads continuation bytes without verifying they fall within the allocated buffer. Truncated multi-byte sequences at the end of a buffer cause reads into adjacent heap memory.

### Integer Overflow in Serialization

The serialization length calculation uses `size_t` arithmetic that can wrap on 32-bit platforms when processing deeply nested structures with long string values, resulting in a small allocation followed by a large write.

### TOCTOU in Serialize

Parson serializes in two passes: first to calculate the required buffer size, then to write the data. If the JSON tree is mutated between passes (e.g., by another thread), the pre-calculated size is too small for the actual write.

### HashDoS via djb2

Parson uses the djb2 hash function for JSON object key lookups. djb2's hash space is predictable — an attacker can craft keys that all map to the same bucket, degrading object operations from O(1) to O(n) per lookup. With enough collisions, parsing a modest-sized JSON document consumes excessive CPU.

### Uncontrolled Recursion (4 Vectors)

The parser recurses for nested arrays, nested objects, mixed nesting, and recursive value resolution without depth limits. Input like `[[[[...` (thousands deep) exhausts the stack.

## Impact

These vulnerabilities affect any application using Parson to parse untrusted JSON input, including:
- Web servers processing JSON API bodies
- Embedded systems using Parson for configuration parsing
- IoT devices with JSON-based protocols
