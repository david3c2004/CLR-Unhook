# CLR Unhooking Tool
- Note: For this to have the effect of a clean CLR, you’d need to manually map the DLL from disk into memory. You cannot use LoadLibraryA/W, because antivirus solutions will detect the DLL load event and may hook it immediately. If you want this behavior, you can look up existing manual mappers on GitHub and integrate one into your codebase. I’m not including one here, as AV vendors generally don’t appreciate that

A native C++ utility that bypasses EDR/AV hooks in the .NET Common Language Runtime by restoring the original `nLoadImage` function implementation.

## Quick Description

This tool removes security product hooks from the CLR's `nLoadImage` function - the critical native entry point that handles all in-memory .NET assembly loading. By reading the clean `clr.dll` from disk and overwriting the hooked function bytes in memory, it restores the original CLR behavior, allowing `Assembly.Load(byte[])` to execute without EDR inspection or scanning.

## What Does This Do?

Modern security products (Defender, CrowdStrike, SentinelOne, etc.) hook the `nLoadImage` function inside `clr.dll` to intercept and scan in-memory .NET assembly loads. This tool unhooks that function by:

1. Reading the clean `clr.dll` from disk
2. Finding the original `nLoadImage` bytes
3. Overwriting the hooked version in memory

After unhooking, `Assembly.Load(byte[])` executes without EDR inspection.

### Understanding nLoadImage

`nLoadImage` is the critical native function that handles **all** in-memory assembly loading in the .NET runtime. It's declared as an `InternalCall` in managed code, meaning it has no C# implementation - instead, it's a direct bridge to native CLR code.

**The Call Chain:**
```
Managed Code (C#)
    ↓
Assembly.Load(byte[])
    ↓
RuntimeAssembly.nLoadImage(...) [InternalCall - no managed body]
    ↓
clr.dll!AssemblyNative::LoadImage (Native C++ implementation)
    ↓
Assembly loaded into AppDomain
```

**Why It's Critical:**

Nearly every in-memory assembly load goes through `nLoadImage`. The `Assembly.Load(byte[])` method and its overloads (including loading with symbol bytes) all invoke `nLoadImage` under the hood. When you call `Assembly.Load(byte[])`, the managed code in `mscorlib.dll` passes your byte array through `RuntimeAssembly.nLoadImage()`, which is marked with `[MethodImpl(MethodImplOptions.InternalCall)]` - meaning its body is empty in C# and execution immediately jumps to native CLR code.

Even dynamic code generation scenarios - serialization frameworks that emit assemblies at runtime, XML serializer generation, and red team tools like Cobalt Strike's `execute-assembly` - all funnel through this single function.

**Native Implementation:**

The `nLoadImage` InternalCall stub in `mscorlib.dll` points to the native C++ function `AssemblyNative::LoadImage` inside `clr.dll`. This function:
- Parses the PE headers from the byte array
- Validates metadata and IL code
- Allocates memory for the assembly
- Registers the assembly in the AppDomain
- Triggers post-load events (ETW, AMSI scanning in .NET 4.8+)
- Handles mixed-mode assemblies (native + managed)
- Enforces strong-name verification

In .NET Framework 4.8+, every `nLoadImage` call automatically passes the assembly bytes to Windows Defender's AMSI (`AmsiScanBuffer`) for scanning before execution, making it a critical chokepoint for security products.

**Function Signature (.NET Framework 4.7+):**
```csharp
[MethodImpl(MethodImplOptions.InternalCall)]
static internal extern Assembly nLoadImage(
    byte[] rawAssembly,              // PE bytes
    byte[] rawSymbolStore,           // Optional PDB bytes
    Evidence evidence,               // CAS evidence (obsolete)
    ref StackCrawlMark stackMark,    // Security stack marker
    bool fIntrospection,             // Reflection-only flag
    bool fSkipIntegrityCheck,        // Skip integrity validation
    SecurityContextSource securityContextSource  // Security context
);
```

When you call `Assembly.Load(byte[])`, it invokes `nLoadImage` with these typical parameters:
```csharp
StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
return RuntimeAssembly.nLoadImage(
    rawAssembly,                            // Your byte array
    null,                                   // rawSymbolStore
    null,                                   // evidence
    ref stackMark,                          // LookForMyCaller
    false,                                  // fIntrospection
    SecurityContextSource.CurrentAssembly   // securityContextSource
);
```

The `fIntrospection` parameter controls whether the assembly is loaded for execution (`false`) or reflection-only inspection (`true`). The `Assembly.ReflectionOnlyLoad(byte[])` method calls `nLoadImage` with `fIntrospection=true`, allowing metadata examination without code execution.

**Why EDR Hooks It:**

Since `nLoadImage` is the **single entry point** for all in-memory assembly loads, EDR products hook it at the native level in `clr.dll`. This allows them to:
- Inspect every assembly before it's loaded
- Scan byte arrays for malicious patterns
- Block execution before .NET even processes the assembly
- Bypass AMSI/ETW evasion techniques (since the hook is below those layers)

Traditional bypasses (AMSI patching, ETW disabling) don't affect CLR-level hooks because they operate at a higher level in the stack. The hook happens **inside** the CLR itself, before AMSI is even invoked.

## Usage

### Local Process (Current Process)

```bash
CLRUnhook.exe
```

Unhooks the CLR in the current process. **Note:** This only works if CLR is already loaded (i.e., running from a .NET application or after loading the CLR manually).

### Remote Process (Target Another Process)

```bash
CLRUnhook.exe powershell.exe

CLRUnhook.exe 1234
```

Unhooks the CLR in a remote process.

## Example Output

### Successful Remote Unhooking

```
=== CLR Unhooking Tool ===

[*] Mode -> Remote Process Unhooking
[*] Target -> PID 21436
[+] Found PID -> 21436
[*] Unhooking CLR->nLoadImage in remote process...
[DEBUG] Remote mode enabled
[DEBUG] Found clr.dll at 0x00007FFD38CB0000
[DEBUG] CLR path -> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
[DEBUG] CLR module size -> 10108928 bytes
[DEBUG] Read 10108928 bytes from remote process
[DEBUG] Searching for 'nLoadImage' in module (size: 10108928)
[DEBUG] Remote base address: 0x00007FFD38CB0000
[DEBUG] Scanning for string 'nLoadImage' (11 bytes)...
[DEBUG] Found string at RVA 0x7c12b8
[DEBUG] Searching for remote pointer: 0x7ffd394712b8
[DEBUG] Found pointer at offset 0x7a4340
[DEBUG] Valid function pointer found at RVA 0x5e4f30
[DEBUG] Found nLoadImage at RVA 0x00000000005E4F30
[DEBUG] Hooked function address -> 0x00007FFD39294F30
[DEBUG] Clean function at offset 0x00000000005E4F30 in disk file
[DEBUG] Reading hooked bytes before patch...
[DEBUG] First 16 bytes BEFORE unhook:
       4C 8B DC 49 89 5B 08 49 89 73 10 4D 89 4B 20 57
[DEBUG] Clean bytes from disk:
       8B 4B 78 E8 88 A9 EA FF C6 44 24 28 00 80 3D A4
[DEBUG] Wrote 30 bytes successfully
[DEBUG] First 16 bytes AFTER unhook:
       8B 4B 78 E8 88 A9 EA FF C6 44 24 28 00 80 3D A4
[DEBUG] VERIFICATION SUCCESS: Patched bytes match clean bytes!
[+] SUCCESS -> CLR nLoadImage unhooked in remote process!
[+] EDR/AV hooks bypassed

[*] Press Enter to exit...
```

### The Hook Chain

```
Managed Code (C#)
    ↓
Assembly.Load(byte[])
    ↓
RuntimeAssembly.nLoadImage(...) [InternalCall]
    ↓
clr.dll!AssemblyNative::LoadImage
    ↓
[EDR HOOK] ← We bypass this
    ↓
Original CLR Code
```

### The Unhooking Process

1. **Locate hooked function** - Finds `nLoadImage` in the loaded `clr.dll` (currently hooked)
2. **Load clean copy** - Reads original `clr.dll` from `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`
3. **Extract clean bytes** - Gets the first 30 bytes of the original function, .net is JIT we dont want to have problems.
4. **Overwrite hook** - Patches the hooked version with clean bytes

### Function Discovery

Uses pattern scanning to locate `nLoadImage`:
1. Search for "nLoadImage" string in module memory
2. Find pointer to that string
3. Locate function pointer adjacent to string pointer
4. Validate address is within module bounds

## Credits

**Technique Research:**
- [Matthew Graeber (@mattifestation)](https://exploitmonday.blogspot.com/2013/11/ReverseEngineeringInternalCallMethods.html) - Reverse engineering InternalCall methods and CLR internals

**Implementation:**
- **HWBP** - CLR unhooking via memory restoration

## Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY.**

Unauthorized use of this tool to bypass security controls may violate computer fraud laws (CFAA, equivalent statutes). Only use on systems you own or have explicit written permission to test.

## References

- [Reverse Engineering InternalCall Methods](https://exploitmonday.blogspot.com/2013/11/ReverseEngineeringInternalCallMethods.html) - Matthew Graeber
- Microsoft .NET Reference Source
- CLR Assembly Loading Pipeline Documentation

---
