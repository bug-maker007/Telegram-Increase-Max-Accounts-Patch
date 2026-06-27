#!/usr/bin/env python3
"""
Telegram Desktop flatpak account limit patcher
Increases kMaxAccounts: 3->33, kPremiumMaxAccounts: 6->36
Finds offsets dynamically — works after updates.

Usage:
    python3 patch_telegram_accounts.py [--dry-run]
"""
import sys, os, struct, shutil, argparse, ctypes, tempfile, subprocess

NEW_KMAX    = 99   # was 3  (max accounts without premium)
NEW_KPREM   = 99   # was 6  (hard cap including premium)

CANDIDATES = [
    os.path.expanduser(
        "~/.local/share/flatpak/app/org.telegram.desktop"
        "/x86_64/stable/active/files/bin/Telegram"),
    "/var/lib/flatpak/app/org.telegram.desktop"
    "/x86_64/stable/active/files/bin/Telegram",
]

# ── fast C scanner compiled on-the-fly ──────────────────────────────────────

_C_SRC = r"""
#include <stdint.h>
#include <string.h>

/* find LEA rdi,[rip+disp32] pointing to target; returns offset or -1 */
int64_t find_lea_rdi(const uint8_t *data, size_t sz, uint64_t target) {
    for (size_t i = 0; i + 7 <= sz; i++) {
        if (data[i]==0x48 && data[i+1]==0x8D && data[i+2]==0x3D) {
            int32_t d; memcpy(&d, data+i+3, 4);
            if ((uint64_t)((int64_t)(i+7) + d) == target) return (int64_t)i;
        }
    }
    return -1;
}

/* find Jcc32/JMP32 pointing to target; returns offset or -1 */
int64_t find_branch_to(const uint8_t *data, size_t sz, uint64_t target) {
    for (size_t i = 0; i + 6 <= sz; i++) {
        if (data[i]==0x0F && (data[i+1]&0xF0)==0x80) {
            int32_t d; memcpy(&d, data+i+2, 4);
            if ((uint64_t)((int64_t)(i+6) + d) == target) return (int64_t)i;
        }
        if (i+5 <= sz && data[i]==0xE9) {
            int32_t d; memcpy(&d, data+i+1, 4);
            if ((uint64_t)((int64_t)(i+5) + d) == target) return (int64_t)i;
        }
    }
    return -1;
}

/* find CALL E8 pointing to target; returns offset or -1 */
int64_t find_call_to(const uint8_t *data, size_t sz, uint64_t target) {
    for (size_t i = 0; i + 5 <= sz; i++) {
        if (data[i]==0xE8) {
            int32_t d; memcpy(&d, data+i+1, 4);
            if ((uint64_t)((int64_t)(i+5) + d) == target) return (int64_t)i;
        }
    }
    return -1;
}
"""

def _load_scanner():
    src = tempfile.NamedTemporaryFile(suffix=".c", delete=False)
    src.write(_C_SRC.encode()); src.close()
    lib = src.name.replace(".c", ".so")
    subprocess.check_call(
        ["gcc", "-O2", "-shared", "-fPIC", "-o", lib, src.name],
        stderr=subprocess.DEVNULL)
    os.unlink(src.name)
    c = ctypes.CDLL(lib)
    for fn in ("find_lea_rdi", "find_branch_to", "find_call_to"):
        f = getattr(c, fn)
        f.restype  = ctypes.c_int64
        f.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64]
    return c, lib

# ── helpers ──────────────────────────────────────────────────────────────────

def u32le(data, off): return struct.unpack_from("<I", data, off)[0]
def i32le(data, off): return struct.unpack_from("<i", data, off)[0]

def bytes_find_all(data, pattern):
    results, idx = [], 0
    while True:
        p = data.find(pattern, idx)
        if p < 0: break
        results.append(p); idx = p + 1
    return results

def scan_back_for_cmp(data, from_off, window=64):
    """Scan backwards from from_off for CMP eax/rax, imm that fits the accounts check."""
    start = max(0, from_off - window)
    chunk = data[start:from_off]
    for j in range(len(chunk)-1, -1, -1):
        b = chunk[j]
        # CMP eax, imm8:  83 F8 xx
        if j >= 2 and chunk[j-2]==0x83 and chunk[j-1]==0xF8:
            return start+j-2, 1, chunk[j]
        # CMP rax, imm8:  48 83 F8 xx
        if j >= 3 and chunk[j-3]==0x48 and chunk[j-2]==0x83 and chunk[j-1]==0xF8:
            return start+j-3, 1, chunk[j]
        # CMP eax, imm32: 3D xx xx xx xx
        if j >= 4 and chunk[j-4]==0x3D:
            return start+j-4, 4, i32le(chunk, j-3)
        # CMP eax, imm32: 81 F8 xx xx xx xx
        if j >= 5 and chunk[j-5]==0x81 and chunk[j-4]==0xF8:
            return start+j-5, 4, i32le(chunk, j-1)
        # CMP rax, imm32: 48 81 F8 xx xx xx xx
        if j >= 6 and chunk[j-6]==0x48 and chunk[j-5]==0x81 and chunk[j-4]==0xF8:
            return start+j-6, 4, i32le(chunk, j-2)
    return None, None, None

# ── main logic ───────────────────────────────────────────────────────────────

def find_patches(data, sc):
    """
    Returns dict of patches: {offset: (old_bytes, new_bytes, description)}
    Raises ValueError with explanation if anything unexpected.
    """
    patches = {}

    # ── 1. Locate assertion message string ──────────────────────────────────
    MSG = b'"_accounts.size() < kPremiumMaxAccounts"'
    positions = bytes_find_all(data, MSG)
    if not positions:
        raise ValueError("Assertion string not found — wrong binary?")
    if len(positions) > 1:
        raise ValueError(f"Assertion string found {len(positions)} times — ambiguous")
    msg_addr = positions[0]
    print(f"  [1] Assertion string @ 0x{msg_addr:x}")

    # ── 2. Find LEA rdi → message (cold assertion path) ─────────────────────
    lea_off = sc.find_lea_rdi(data, len(data), msg_addr)
    if lea_off < 0:
        raise ValueError("LEA rdi → assertion string not found")
    print(f"  [2] LEA rdi,[msg] @ 0x{lea_off:x}")

    # ── 3. Find cold-block entry (has stack-canary check before the LEA) ────
    #  Pattern just before LEA: mov rax,[rbp-X]; sub rax,[fs:0x28]; jne epilogue; mov edx,272; lea rsi,[file]; lea rdi,[msg]
    #  We search backwards for "mov edx, 272" (BA 10 01 00 00) which is line 272 in main_domain.cpp.
    LINE272 = b'\xba\x10\x01\x00\x00'   # MOV edx, 272
    # scan the 80 bytes before the LEA
    chunk = data[max(0, lea_off-80):lea_off]
    rel = chunk.rfind(LINE272)
    if rel < 0:
        raise ValueError("MOV edx,272 not found before LEA — line number may have changed")
    movedx_off = max(0, lea_off-80) + rel
    print(f"  [3] MOV edx,272 @ 0x{movedx_off:x}")

    # cold block entry = the mov rax,[rbp-X] before MOV edx,272
    # It starts with: 48 8B 45 xx  (MOV rax,[rbp+disp8])
    chunk2 = data[max(0, movedx_off-20):movedx_off]
    cold_entry = None
    for k in range(len(chunk2)-3, -1, -1):
        if chunk2[k]==0x48 and chunk2[k+1]==0x8B and chunk2[k+2]==0x45:
            cold_entry = max(0, movedx_off-20) + k
            break
    if cold_entry is None:
        raise ValueError("Could not locate cold-block entry (MOV rax,[rbp-X])")
    print(f"  [4] Cold block entry @ 0x{cold_entry:x}")

    # ── 4. Find the JG/JNE that branches to the cold block ──────────────────
    branch_off = sc.find_branch_to(data, len(data), cold_entry)
    if branch_off < 0:
        raise ValueError("No branch targeting cold block found")
    print(f"  [5] JG/branch @ 0x{branch_off:x} -> 0x{cold_entry:x}")

    # ── 5. Find CMP before the branch ────────────────────────────────────────
    cmp_off, imm_sz, cmp_val = scan_back_for_cmp(data, branch_off)
    if cmp_off is None:
        raise ValueError("CMP instruction before branch not found")

    # Decode what the CMP is comparing (raw byte diff vs account-count limit)
    # If imm_sz==1 or imm_sz==4, cmp_val is the raw byte difference threshold
    # kPremiumMaxAccounts_old = cmp_val / sizeof(element) + 1  (for JG semantics)
    # OR cmp_val is already element count (if SAR was done first)
    # Detect which case: look for SAR/SHR between sub and cmp
    region = data[cmp_off - 12 : cmp_off]
    has_sar = any(
        (region[i]==0x48 and region[i+1]==0xC1 and region[i+2]==0xF8) or  # SAR rax, imm8
        (region[i]==0xC1 and region[i+1]==0xF8) or                         # SAR eax, imm8
        (region[i]==0x48 and region[i+1]==0xD1 and region[i+2]==0xF8) or  # SAR rax,1
        (region[i]==0x48 and region[i+1]==0xC1 and region[i+2]==0xE8)     # SHR rax, imm8
        for i in range(len(region)-2)
    )

    if has_sar:
        # CMP is directly comparing element count
        old_kprem = cmp_val + 1
        sizeof_elem = None
    else:
        # CMP is comparing raw byte diff; figure out element size
        # by looking at the SAR shift amount in the sub/sar sequence nearby
        # Heuristic: cmp_val = (kPremiumMaxAccounts-1) * sizeof
        # We know old kPremiumMaxAccounts = 6, so sizeof = cmp_val / 5
        if cmp_val % 5 == 0:
            sizeof_elem = cmp_val // 5
            old_kprem = cmp_val // sizeof_elem + 1
        else:
            # Fallback: trust the value is (kPrem-1)*sizeof
            sizeof_elem = None
            old_kprem = None  # can't determine confidently

    print(f"  [6] CMP @ 0x{cmp_off:x}  val={cmp_val}  has_sar={has_sar}  "
          f"old_kPremiumMaxAccounts≈{old_kprem}  sizeof≈{sizeof_elem}")

    if old_kprem is not None and old_kprem not in (3, 4, 5, 6, 7, 8, 10):
        raise ValueError(f"Unexpected kPremiumMaxAccounts={old_kprem}, refusing to patch")

    # Build new CMP value
    if has_sar:
        new_cmp_val = NEW_KPREM - 1
    else:
        new_cmp_val = (NEW_KPREM - 1) * sizeof_elem

    # Now rebuild the instruction region (mov+sub+cmp+jcc) to fit new_cmp_val
    # We need the SUB instruction to find where the mov/sub pair starts
    # Find: MOV r,[mem]; SUB r,[mem] just before CMP
    # Strategy: look at the 12 bytes before cmp_off for MOV+SUB pair
    before = data[cmp_off - 12 : cmp_off]
    mov_sub_start = None
    for k in range(len(before)-7, -1, -1):
        b = before[k:k+8]
        # MOV rax,[rbx+disp8] + SUB rax,[rbx+disp8]: 48 8B 4? ?? 48 2B 4? ??
        if (b[0]==0x48 and b[1]==0x8B and b[4]==0x48 and b[5]==0x2B):
            mov_sub_start = cmp_off - 12 + k
            break
        # MOV eax,[rbx+disp8] + SUB eax,[rbx+disp8]: 8B 4? ?? 2B 4? ??
        if (b[0]==0x8B and b[3]==0x2B):
            mov_sub_start = cmp_off - 12 + k
            break

    # Read the JCC instruction (at branch_off) to get its opcode and old target
    jcc_bytes = data[branch_off:branch_off+6]
    jcc_opcode = jcc_bytes[1]  # e.g. 0x8F for JG

    if new_cmp_val <= 0x7F:
        # Fits in imm8 — use 48 83 F8 xx (CMP rax, imm8)
        new_cmp_instr = bytes([0x48, 0x83, 0xF8, new_cmp_val & 0xFF])
    elif new_cmp_val <= 0x7FFF_FFFF:
        # Need imm32 — try to use eax form to save bytes
        new_cmp_instr = bytes([0x3D]) + struct.pack("<I", new_cmp_val)  # CMP eax, imm32 (5 bytes)
    else:
        raise ValueError(f"new_cmp_val={new_cmp_val} too large")

    # Rebuild the MOV+SUB+CMP+JCC sequence
    if mov_sub_start is not None:
        old_seq_start = mov_sub_start
        old_seq_end   = branch_off + 6  # end of JCC
        old_seq       = data[old_seq_start:old_seq_end]

        # Try to fit new sequence in same byte count
        old_mov_sub = old_seq[:cmp_off - mov_sub_start]

        # Detect if original uses 64-bit or 32-bit MOV/SUB
        uses_rex = old_mov_sub[0] == 0x48

        if uses_rex and new_cmp_val > 0x7F:
            # Switch MOV/SUB to 32-bit (saves 2 bytes) to accommodate larger CMP
            # 48 8B 43 xx -> 8B 43 xx  (save 1)
            # 48 2B 43 xx -> 2B 43 xx  (save 1)
            new_mov_sub = bytes([old_mov_sub[1], old_mov_sub[2], old_mov_sub[3],
                                 old_mov_sub[5], old_mov_sub[6], old_mov_sub[7]])
        else:
            new_mov_sub = old_mov_sub

        # Build new JCC with recalculated target
        jcc_instr_start = old_seq_start + len(new_mov_sub) + len(new_cmp_instr)
        jcc_offset = cold_entry - (jcc_instr_start + 6)
        new_jcc = bytes([0x0F, jcc_opcode]) + struct.pack("<i", jcc_offset)

        new_seq = new_mov_sub + new_cmp_instr + new_jcc
        # Pad or trim to match old length
        old_len = len(old_seq)
        if len(new_seq) < old_len:
            new_seq += b'\x90' * (old_len - len(new_seq))
        elif len(new_seq) > old_len:
            raise ValueError(
                f"New sequence is {len(new_seq)-old_len} bytes longer than original "
                f"({old_len} bytes) — cannot patch without overwriting adjacent code.\n"
                f"  old={old_seq.hex()}\n  new={new_seq.hex()}")

        patches[old_seq_start] = (old_seq, new_seq,
            f"Domain::add() assertion: CMP val {cmp_val}→{new_cmp_val} (allows {NEW_KPREM} accounts)")
    else:
        # Fallback: just patch the immediate in the CMP instruction
        if imm_sz == 1:
            old_b = data[cmp_off : cmp_off + len(new_cmp_instr)]
            if new_cmp_val <= 0x7F:
                new_b = old_b[:-1] + bytes([new_cmp_val])
                patches[cmp_off] = (old_b, new_b, f"CMP imm: {cmp_val}→{new_cmp_val}")
            else:
                raise ValueError("CMP immediate too large for fallback 1-byte patch")
        else:
            raise ValueError("Cannot patch CMP in fallback mode for imm32")

    # ── 6. Find maxAccounts() via call chain ─────────────────────────────────
    #  Domain::add() is the function containing branch_off.
    #  Find its ENDBR64 (F3 0F 1E FA) start by scanning backwards.
    fn_start = branch_off
    for k in range(branch_off - 1, max(0, branch_off - 0x800), -1):
        if data[k:k+4] == b'\xF3\x0F\x1E\xFA':  # endbr64
            fn_start = k
            break
    print(f"  [7] Domain::add() starts @ 0x{fn_start:x}")

    # Find all callers of Domain::add()
    callers = []
    idx = 0
    while True:
        pos = data.find(b'\xE8', idx)
        if pos < 0: break
        off = i32le(data, pos+1)
        if (pos + 5 + off) == fn_start:
            callers.append(pos)
        idx = pos + 1

    if not callers:
        raise ValueError("No callers of Domain::add() found")
    print(f"  [8] Caller(s) of Domain::add(): {[hex(c) for c in callers]}")
    # Use the first caller (addActivated)
    caller_off = callers[0]

    # In addActivated(), the CALL just before call-to-add is call-to-maxAccounts
    # Scan backwards for the previous E8 (CALL) instruction
    maxacc_call_off = None
    for k in range(caller_off - 1, max(0, caller_off - 0x80), -1):
        if data[k] == 0xE8:
            maxacc_call_off = k
            break
    if maxacc_call_off is None:
        raise ValueError("Cannot find CALL to maxAccounts() before CALL to add()")
    maxacc_fn_off = maxacc_call_off + 5 + i32le(data, maxacc_call_off + 1)
    print(f"  [9] maxAccounts() @ 0x{maxacc_fn_off:x}")

    # ── 7. Parse maxAccounts() to find kMaxAccounts and kPremiumMaxAccounts ──
    #  Function body contains:
    #    counting loop …
    #    lea eax, [r??+kMaxAccounts]   ← ADD variant
    #    mov e?x, kPremiumMaxAccounts
    #    cmp/cmovg                      ← min()
    #    ret
    #  Also an early-exit path: mov eax, kMaxAccounts; ret

    fn = data[maxacc_fn_off : maxacc_fn_off + 0x200]

    def find_lea_plus_k(chunk):
        """Find LEA eax/ecx/edx, [reg+imm8] or ADD reg, imm8 followed by MOV reg, imm32"""
        for i in range(len(chunk)-10):
            # LEA eax, [r??+imm8]: 41 8D 44 24 xx  or  8D 40 xx  etc.
            # More generally: 41 8D ?? 24 xx (r12 variant) or 8D ?? xx
            # After it: BA/BF/BE xx 00 00 00 (MOV e?x, imm32)
            b = chunk[i]
            lea_imm = None
            lea_len = 0
            # 41 8D ?? 24 imm8   (r8-r15 with SIB for r12)
            if b==0x41 and chunk[i+1]==0x8D and chunk[i+3]==0x24:
                lea_imm = chunk[i+4]; lea_len = 5
            # 8D 4? imm8  (rax-rdi without SIB, mod=01)
            elif b==0x8D and (chunk[i+1]&0xC0)==0x40 and (chunk[i+1]&0x07)!=0x04:
                lea_imm = chunk[i+2]; lea_len = 3
            # ADD eax/ecx/edx, imm8
            elif b==0x83 and (chunk[i+1]&0xF8)==0xC0:
                lea_imm = chunk[i+2]; lea_len = 3
            elif b==0x41 and chunk[i+1]==0x83 and (chunk[i+2]&0xF8)==0xC0:
                lea_imm = chunk[i+3]; lea_len = 4

            if lea_imm is not None and 1 <= lea_imm <= 10:
                # Check next instruction is MOV e?x, imm32
                nxt = i + lea_len
                if 0xB8 <= chunk[nxt] <= 0xBF:
                    mov_imm = u32le(chunk, nxt+1)
                    if 1 <= mov_imm <= 10:
                        yield maxacc_fn_off+i, lea_imm, maxacc_fn_off+nxt, mov_imm

    candidates = list(find_lea_plus_k(fn))
    if not candidates:
        raise ValueError("LEA/ADD+MOV pattern for kMaxAccounts+kPremiumMaxAccounts not found in maxAccounts()")

    # Pick the pair where lea_imm + mov_imm looks right (typically kMax=3, kPrem=6)
    # After patching we'll change both; pick lowest lea_imm as kMaxAccounts
    lea_off2, old_kmax, mov_off2, old_kprem2 = min(candidates, key=lambda x: x[1])
    print(f"  [10] maxAccounts() LEA: 0x{lea_off2:x} kMaxAccounts={old_kmax}")
    print(f"       maxAccounts() MOV: 0x{mov_off2:x} kPremiumMaxAccounts={old_kprem2}")

    # Sanity check
    if old_kmax not in range(1, 11) or old_kprem2 not in range(1, 11):
        raise ValueError(f"Unexpected values kMax={old_kmax} kPrem={old_kprem2}")

    # Patch LEA imm byte (last byte of LEA instruction)
    lea_imm_off = lea_off2 + (5 if data[lea_off2]==0x41 else 3) - 1
    if data[lea_imm_off] != old_kmax:
        # Try +1 offset (for ADD r64 with REX prefix)
        lea_imm_off += 1
    old_byte = data[lea_imm_off]
    patches[lea_imm_off] = (
        bytes([old_byte]), bytes([NEW_KMAX & 0xFF]),
        f"kMaxAccounts {old_kmax}→{NEW_KMAX} (LEA/ADD immediate)")

    # Patch MOV immediate (byte 1 of MOV e?x, imm32)
    old_byte2 = data[mov_off2 + 1]
    patches[mov_off2 + 1] = (
        bytes([old_byte2]), bytes([NEW_KPREM & 0xFF]),
        f"kPremiumMaxAccounts {old_kprem2}→{NEW_KPREM} (MOV immediate)")

    # ── 8. Find the early-return path (empty accounts: mov eax, kMaxAccounts; ret) ──
    # Scan maxAccounts() for: B8 kmax 00 00 00  (MOV eax, kMaxAccounts)
    early_ret_pat = bytes([0xB8, old_kmax, 0x00, 0x00, 0x00])
    rel = fn.find(early_ret_pat)
    if rel >= 0:
        er_off = maxacc_fn_off + rel + 1  # byte 1 is the immediate
        patches[er_off] = (
            bytes([old_kmax]), bytes([NEW_KMAX & 0xFF]),
            f"kMaxAccounts {old_kmax}→{NEW_KMAX} (early-return MOV eax)")
        print(f"  [11] Early-return MOV eax,{old_kmax} @ 0x{maxacc_fn_off+rel:x}")
    else:
        print(f"  [11] Early-return path not found (may be optimized out — OK)")

    return patches


def apply_patches(path, patches, dry_run=False):
    print(f"\n{'DRY RUN — ' if dry_run else ''}Applying {len(patches)} patch(es) to:\n  {path}\n")
    with open(path, 'r+b' if not dry_run else 'rb') as f:
        for off in sorted(patches):
            old_b, new_b, desc = patches[off]
            f.seek(off)
            cur = f.read(len(old_b))
            if cur != old_b:
                raise ValueError(
                    f"MISMATCH at 0x{off:x}: expected {old_b.hex()} got {cur.hex()}\n"
                    f"  ({desc})")
            if not dry_run:
                f.seek(off)
                f.write(new_b)
            print(f"  {'[dry]' if dry_run else '[OK] '} 0x{off:x}  {old_b.hex()} → {new_b.hex()}")
            print(f"         {desc}")


def main():
    global NEW_KMAX, NEW_KPREM
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Find patches but don't write anything")
    ap.add_argument("--binary", help="Path to Telegram binary (auto-detected if omitted)")
    ap.add_argument("--max", type=int, default=NEW_KMAX,
                    help=f"kMaxAccounts value (default: {NEW_KMAX}, original: 3)")
    ap.add_argument("--premium-max", type=int, default=NEW_KPREM,
                    help=f"kPremiumMaxAccounts value (default: {NEW_KPREM}, original: 6)")
    args = ap.parse_args()

    path = args.binary
    if not path:
        for c in CANDIDATES:
            if os.path.exists(c):
                path = c; break
    if not path:
        sys.exit("Telegram binary not found. Use --binary PATH")

    NEW_KMAX  = args.max
    NEW_KPREM = args.premium_max
    if NEW_KMAX > 127 or NEW_KPREM > 127:
        sys.exit("Values must be ≤ 127")

    print(f"Target: {path}")
    print(f"Size:   {os.path.getsize(path):,} bytes")
    print(f"Limits: kMaxAccounts={NEW_KMAX}, kPremiumMaxAccounts={NEW_KPREM}\n")

    print("Compiling scanner…")
    sc, sc_lib = _load_scanner()

    print("Loading binary…")
    with open(path, 'rb') as f:
        data = f.read()

    print("Searching for patch sites…")
    try:
        patches = find_patches(data, sc)
    finally:
        os.unlink(sc_lib)

    if not args.dry_run:
        backup = path + ".orig"
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
            print(f"\nBackup saved → {backup}")
        else:
            print(f"\nBackup already exists → {backup}")

    apply_patches(path, patches, dry_run=args.dry_run)

    if not args.dry_run:
        print(f"\nDone! kMaxAccounts={NEW_KMAX}, kPremiumMaxAccounts={NEW_KPREM}")
        print("Restart Telegram to apply.")

if __name__ == "__main__":
    main()
