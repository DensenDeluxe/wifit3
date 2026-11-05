# Wolf Tools Analysis for wifit3 CPU Cracking

## WEPWolf Analysis

**Type:** Rust binary (101 files)
**Purpose:** Pure CPU WEP cracking - NO hashcat needed!

### Key Features for wifit3 Integration

#### 1. PTW Attack (Pyshkin-Tews-Weinmann)
- **Location:** `WEPWolf/src/attack/ptw.rs`
- **How it works:** Statistical RC4 bias analysis
- **Advantage:** Cracks WEP from ordinary captured traffic
- **Speed:** "fraction of a second" with 30k IVs
- **Python Integration:** Algorithm is pure math - easily ported!

#### 2. KoreK Attack (17 Correlations)
- **Location:** `WEPWolf/src/attack/korek.rs`
- **How it works:** Enhanced FMS with 17 RC4 correlations
- **Advantage:** Works with fewer weak IVs than FMS

#### 3. FMS Attack (Fluhrer-Mantin-Shamir)
- **Location:** `WEPWolf/src/attack/fms.rs`
- **How it works:** Original WEP statistical attack
- **Advantage:** Simple, well-understood

#### 4. RC4 Bias Attack (Sepehrdad "Smashing WEP")
- **Location:** `WEPWolf/src/attack/bias.rs`
- **How it works:** Database of RC4 biases voted together
- **Advantage:** Recovers from fewer packets than PTW!
- **Unique:** aircrack-ng does NOT have this!

#### 5. Dictionary Attack
- **Location:** `WEPWolf/src/attack/dict.rs`
- **Features:**
  - Built-in COMMON_KEYS (1234567890, 12345, etc.)
  - Wordlist support (raw hex or ASCII)
  - Near-free to check

#### 6. Keygen Attack
- **Location:** `WEPWolf/src/attack/keygen.rs`
- **Derives WEP keys from passphrases:**
  - Neesus-Datacom (40-bit)
  - MD5 (104-bit)

#### 7. Brute Force
- **Location:** `WEPWolf/src/attack/brute.rs`
- **Optimized:** Known-plaintext prefilter (SNAP header)
- **Last resort:** WEP-40 only (slow)

### Core Algorithm (Pure Math!)

```rust
// PTW vote accumulation (from ptw.rs)
pub(crate) fn recover(
    primary: &[IvSample],      // All IV samples
    secondary: &[IvSample],    // ARP keystreams
    keylen: usize,             // 5, 13, or 29 bytes
    verifier: &Verifier,       // CRC-32 ICV checker
    brute_tail: usize,         // Brute force trailing bytes
    mp_weight: i32,            // Maitra-Paul weight
) -> Option<WepKey> {
    // 1. Tally Klein + Maitra-Paul sigma votes
    // 2. Search top-k candidates per position
    // 3. Verify with RC4 decrypt + CRC-32 ICV check
}
```

### Why This is PERFECT for wifit3

1. **NO External Dependencies:** Pure Rust, no hashcat
2. **SIMD Optimized:** `src/simd.rs` has AVX2/SSE2 acceleration
3. **Parallel:** Uses rayon for multi-core
4. **Verified:** Every key RC4-decrypts frames + CRC-32 check
5. **Fast:** >=200 MB/s on NVMe
6. **Complete:** 7 attack types covering all WEP scenarios

## WPAWolf Analysis

**Type:** Rust binary (406 files)
**Purpose:** WPA handshake extraction → hashcat format

### Key Features

- **Extracts:** WPA/WPA2/WPA3 handshakes and PMKIDs
- **Output:** Hashcat mode 22000 format
- **NOT a cracker:** Just extracts hashes (like hcxpcapngtool)
- **Cross-file pairing:** M1 in file A + M2 in file B
- **20 PMKID extraction sites:** Every spec-defined location

### Limitation for wifit3

WPAWolf is an **extractor**, not a cracker. It needs hashcat for actual cracking.

## Integration Recommendation

### WEP: ✅ Full Integration

Port WEPWolf algorithms to Python:
1. **PTW Attack** - Main statistical attack
2. **RC4 Bias Attack** - Unique advantage over aircrack-ng
3. **Dictionary + Keygen** - Built-in weak keys
4. **Verifier** - CRC-32 ICV validation

### WPA: ⚠️ Partial Integration

WPAWolf extracts hashes but doesn't crack them. For CPU cracking:
- Use existing `wifit3/vault/tools/cpu_crack.py`
- Or integrate hashcat as external tool

## Implementation Plan

### Phase 1: WEP CPU Cracking (High Priority)

```python
# src/wifit3/crack/wepwolf.py
class WepWolfCracker:
    """Pure Python WEP cracker based on WEPWolf algorithms."""
    
    def crack_ptw(self, ivs: list, arp_keystreams: list) -> Optional[bytes]:
        """PTW statistical attack."""
        pass
    
    def crack_bias(self, ivs: list) -> Optional[bytes]:
        """RC4 bias attack (Smashing WEP)."""
        pass
    
    def crack_dict(self, wordlist: list) -> Optional[bytes]:
        """Dictionary attack with COMMON_KEYS."""
        pass
```

### Phase 2: WEPWolf Binary Integration (Medium Priority)

Compile WEPWolf as static binary and call it:
```python
# src/wifit3/vault/tools/wepwolf.py
class WepWolfTool(VaultTool):
    """External WEPWolf binary for fast WEP cracking."""
    name = "wepwolf"
```

### Phase 3: SIMD Optimization (Low Priority)

Use Cython or Rust extension for SIMD-accelerated RC4.

## Conclusion

**WEPWolf is a GOLDMINE for wifit3!**

- ✅ Pure CPU WEP cracking (no hashcat)
- ✅ 7 attack types (PTW, KoreK, FMS, Bias, Dict, Keygen, Brute)
- ✅ RC4 bias attack NOT in aircrack-ng
- ✅ Easily portable to Python (pure math)
- ✅ Verified with CRC-32 ICV checks

**WPAWolf is good but not a cracker:**
- ⚠️ Extracts hashes only
- ⚠️ Needs hashcat for cracking
- ✅ Better than hcxpcapngtool (20 PMKID sites)
