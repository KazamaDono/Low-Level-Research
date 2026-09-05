# Fastsocket — Linux Kernel Module Vulnerability Research

**Target:** [Fastsocket](https://github.com/fastos/fastsocket) (Linux kernel-level socket optimization module)  
**Findings:** 3 critical vulnerabilities  
**Severity:** Critical  

## Overview

Fastsocket is a kernel module designed to improve network socket performance on multi-core systems. Audit revealed three critical memory corruption vulnerabilities that can be triggered from userspace, potentially leading to kernel code execution or denial of service.

## Vulnerabilities

### 1. Heap Buffer Overflow in `fsocket_fd_set`

**Type:** Heap buffer overflow  
**Impact:** Kernel code execution / privilege escalation  

The `fsocket_fd_set` function allocates a kernel buffer to track file descriptors but does not properly validate the fd count parameter from userspace. Passing a crafted fd value causes the function to write beyond the allocated heap buffer in kernel space.

An attacker with the ability to open a Fastsocket connection can corrupt adjacent kernel heap objects, potentially overwriting function pointers or kernel data structures to achieve arbitrary code execution in ring 0.

### 2. Stack Buffer Overflow in Argument Parsing

**Type:** Stack buffer overflow  
**Impact:** Kernel code execution / privilege escalation  

The module's argument parsing routine copies user-supplied configuration strings to a fixed-size stack buffer without length validation. Long arguments overflow the kernel stack frame, overwriting the saved return address.

Since the kernel stack is not protected by ASLR in the same way as userspace (kernel base addresses are more predictable), this is directly exploitable for control-flow hijacking.

### 3. Use-After-Free in Pool Allocator

**Type:** Use-after-free  
**Impact:** Kernel code execution / information leak  

Fastsocket's custom connection pool allocator frees socket structures without properly nullifying references in the active connection table. A subsequent allocation can reuse the freed memory while stale pointers in the connection table still reference it.

This creates a use-after-free condition where:
1. Attacker triggers a socket close (memory freed)
2. Attacker sprays the kernel heap to reclaim the freed chunk with controlled data
3. A stale pointer in the connection table dereferences the attacker-controlled memory
4. Function pointer fields in the fake structure redirect execution

## Impact

All three vulnerabilities are exploitable from userspace on systems running the Fastsocket module. Successful exploitation yields kernel code execution (ring 0), enabling:
- Full privilege escalation from any user to root
- Kernel rootkit installation
- Container/VM escape in virtualized environments
- Complete system compromise

## Affected

Any Linux system running the Fastsocket kernel module. The module must be loaded for exploitation — it is not part of the mainline Linux kernel.
