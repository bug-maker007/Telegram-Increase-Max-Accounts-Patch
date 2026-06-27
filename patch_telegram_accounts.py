#!/usr/bin/env python3
"""
Telegram Desktop flatpak account limit patcher
Finds patch sites dynamically — works after updates.

Usage:
    python3 patch_telegram_accounts.py [--dry-run] [--max N] [--premium-max N]
"""
import sys, os, struct, shutil, argparse

NEW_KMAX  = 99  # kMaxAccounts        (original: 3)
NEW_KPREM = 99  # kPremiumMaxAccounts (original: 6)

CANDIDATES = [
    os.path.expanduser(
        "~/.local/share/flatpak/app/org.telegram.desktop"
        "/x86_64/stable/active/files/bin/Telegram"),
    "/var/lib/flatpak/app/org.telegram.desktop"
    "/x86_64/stable/active/files/bin/Telegram",
]

# ── binary search helpers ────────────────────────────────────────────────────

def i32(data, off):
    return struct.unpack_from("<i", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def find_lea_rdi(data, target):
    """Find LEA rdi,[rip+disp32] (48 8D 3D ..) pointing to target address."""
    idx = 0
    while True:
        pos = data.find(b'\x48\x8d\x3d', idx)
        if pos < 0:
            return -1
        if pos + 7 + i32(data, pos + 3) == target:
            return pos
        idx = pos + 1

def find_branch_to(data, target):
    """Find Jcc32 (0F 8x ..) or JMP32 (E9 ..) pointing to target address."""
    idx = 0
    while True:
        pos = data.find(b'\x0f', idx)
        if pos < 0:
            break
        if pos + 6 <= len(data) and (data[pos + 1] & 0xF0) == 0x80:
            if pos + 6 + i32(data, pos + 2) == target:
                return pos
        idx = pos + 1
    idx = 0
    while True:
        pos = data.find(b'\xe9', idx)
        if pos < 0:
            return -1
        if pos + 5 <= len(data) and pos + 5 + i32(data, pos + 1) == target:
            return pos
        idx = pos + 1

def find_calls_to(data, target):
    """Return list of offsets of CALL E8 instructions targeting address."""
    results, idx = [], 0
    while True:
        pos = data.find(b'\xe8', idx)
        if pos < 0:
            return results
        if pos + 5 <= len(data) and pos + 5 + i32(data, pos + 1) == target:
            results.append(pos)
        idx = pos + 1

# ── patch-site discovery ─────────────────────────────────────────────────────

def find_patches(data):
    patches = {}

    # 1. Unique assertion string hard-coded in main_domain.cpp
    MSG = b'"_accounts.size() < kPremiumMaxAccounts"'
    hits = []
    idx = 0
    while True:
        p = data.find(MSG, idx)
        if p < 0: break
        hits.append(p); idx = p + 1
    if not hits:
        raise ValueError("Assertion string not found — wrong binary?")
    if len(hits) > 1:
        raise ValueError(f"Assertion string found {len(hits)} times — ambiguous")
    msg_addr = hits[0]
    print(f"  [1] Assertion string        @ 0x{msg_addr:x}")

    # 2. LEA rdi,[msg] — start of cold assertion path in Domain::add()
    lea_off = find_lea_rdi(data, msg_addr)
    if lea_off < 0:
        raise ValueError("LEA rdi → assertion string not found")
    print(f"  [2] LEA rdi,[msg]           @ 0x{lea_off:x}")

    # 3. MOV edx, 272  (line number for Expects() at line 272 in main_domain.cpp)
    #    Located in the 80 bytes before the LEA
    LINE272 = b'\xba\x10\x01\x00\x00'
    chunk = data[max(0, lea_off - 80) : lea_off]
    rel = chunk.rfind(LINE272)
    if rel < 0:
        raise ValueError("MOV edx,272 not found before LEA — source line number changed?")
    movedx_off = max(0, lea_off - 80) + rel
    print(f"  [3] MOV edx,272             @ 0x{movedx_off:x}")

    # 4. Cold-block entry = MOV rax,[rbp-X] just before MOV edx,272
    #    (stack canary check before calling assertion::fail)
    chunk2 = data[max(0, movedx_off - 20) : movedx_off]
    cold_entry = None
    for k in range(len(chunk2) - 3, -1, -1):
        if chunk2[k] == 0x48 and chunk2[k+1] == 0x8B and chunk2[k+2] == 0x45:
            cold_entry = max(0, movedx_off - 20) + k
            break
    if cold_entry is None:
        raise ValueError("Cold-block entry (MOV rax,[rbp-X]) not found")
    print(f"  [4] Cold block entry        @ 0x{cold_entry:x}")

    # 5. Conditional branch (JG/JNE) that enters the cold block on failure
    branch_off = find_branch_to(data, cold_entry)
    if branch_off < 0:
        raise ValueError("No branch targeting cold block found")
    print(f"  [5] Branch to cold block    @ 0x{branch_off:x}")

    # 6. CMP instruction just before the branch
    #    Scan backwards through up to 64 bytes looking for recognisable CMP forms.
    start = max(0, branch_off - 64)
    window = data[start : branch_off]
    cmp_off = cmp_imm = imm_sz = None
    for j in range(len(window) - 1, -1, -1):
        # CMP eax, imm8:  83 F8 xx
        if j >= 2 and window[j-2] == 0x83 and window[j-1] == 0xF8:
            cmp_off, imm_sz, cmp_imm = start + j - 2, 1, window[j]
            break
        # CMP rax, imm8:  48 83 F8 xx
        if j >= 3 and window[j-3] == 0x48 and window[j-2] == 0x83 and window[j-1] == 0xF8:
            cmp_off, imm_sz, cmp_imm = start + j - 3, 1, window[j]
            break
        # CMP eax, imm32: 3D xx xx xx xx
        if j >= 4 and window[j-4] == 0x3D:
            cmp_off, imm_sz, cmp_imm = start + j - 4, 4, u32(window, j - 3)
            break
        # CMP rax, imm32: 48 81 F8 xx xx xx xx
        if j >= 6 and window[j-6] == 0x48 and window[j-5] == 0x81 and window[j-4] == 0xF8:
            cmp_off, imm_sz, cmp_imm = start + j - 6, 4, u32(window, j - 2)
            break
        # CMP eax, imm32: 81 F8 xx xx xx xx
        if j >= 5 and window[j-5] == 0x81 and window[j-4] == 0xF8:
            cmp_off, imm_sz, cmp_imm = start + j - 5, 4, u32(window, j - 1)
            break
    if cmp_off is None:
        raise ValueError("CMP instruction before branch not found")

    # Is the raw byte-diff compared directly, or was SAR/SHR done first?
    region = data[cmp_off - 12 : cmp_off]
    has_sar = any(
        (region[i] == 0x48 and region[i+1] == 0xC1 and region[i+2] in (0xF8, 0xE8)) or
        (region[i] == 0xC1 and region[i+1] in (0xF8, 0xE8)) or
        (region[i] == 0x48 and region[i+1] == 0xD1 and region[i+2] == 0xF8)
        for i in range(len(region) - 2)
    )

    if has_sar:
        sizeof_elem = 1
        old_kprem = cmp_imm + 1
    else:
        # cmp_imm = (kPremiumMaxAccounts - 1) * sizeof(AccountWithIndex)
        # sizeof == 16 normally; verify by checking cmp_imm % 5 == 0
        sizeof_elem = cmp_imm // 5 if cmp_imm % 5 == 0 else 16
        old_kprem = cmp_imm // sizeof_elem + 1

    print(f"  [6] CMP immediate           = {cmp_imm}  "
          f"(sizeof={sizeof_elem}, old kPremiumMaxAccounts≈{old_kprem})")

    if old_kprem not in range(1, 12):
        raise ValueError(f"Unexpected old kPremiumMaxAccounts={old_kprem}, refusing")

    new_cmp_val = (NEW_KPREM - 1) * sizeof_elem

    # Find MOV rax + SUB rax pair that precedes the CMP (up to 12 bytes back)
    before = data[cmp_off - 12 : cmp_off]
    mov_sub_start = None
    for k in range(len(before) - 7, -1, -1):
        b = before[k : k + 8]
        if b[0] == 0x48 and b[1] == 0x8B and b[4] == 0x48 and b[5] == 0x2B:
            mov_sub_start = cmp_off - 12 + k
            break
        if b[0] == 0x8B and b[3] == 0x2B:
            mov_sub_start = cmp_off - 12 + k
            break

    jcc_opcode = data[branch_off + 1]  # e.g. 0x8F = JG

    # Choose CMP encoding for new value
    if new_cmp_val <= 0x7F:
        new_cmp = bytes([0x48, 0x83, 0xF8, new_cmp_val])   # CMP rax, imm8
    else:
        new_cmp = b'\x3d' + struct.pack("<I", new_cmp_val)  # CMP eax, imm32

    if mov_sub_start is not None:
        old_seq = data[mov_sub_start : branch_off + 6]
        old_mov_sub = old_seq[: cmp_off - mov_sub_start]

        # Drop REX prefix from MOV/SUB to reclaim 2 bytes when CMP grows
        if old_mov_sub[0] == 0x48 and new_cmp_val > 0x7F:
            new_mov_sub = bytes([
                old_mov_sub[1], old_mov_sub[2], old_mov_sub[3],  # MOV eax without REX
                old_mov_sub[5], old_mov_sub[6], old_mov_sub[7],  # SUB eax without REX
            ])
        else:
            new_mov_sub = bytes(old_mov_sub)

        jcc_start = mov_sub_start + len(new_mov_sub) + len(new_cmp)
        jcc_disp  = cold_entry - (jcc_start + 6)
        new_jcc   = bytes([0x0F, jcc_opcode]) + struct.pack("<i", jcc_disp)

        new_seq = new_mov_sub + new_cmp + new_jcc
        pad = len(old_seq) - len(new_seq)
        if pad < 0:
            raise ValueError(
                f"New sequence {len(new_seq)}B > original {len(old_seq)}B — cannot fit")
        new_seq += b'\x90' * pad

        patches[mov_sub_start] = (
            bytes(old_seq), new_seq,
            f"Domain::add() assertion: allow {NEW_KPREM} accounts "
            f"(CMP {cmp_imm}→{new_cmp_val})")
    else:
        raise ValueError("MOV+SUB pair not found before CMP — cannot rebuild sequence")

    # 7. Locate Domain::add() function start (ENDBR64 = F3 0F 1E FA)
    fn_add = branch_off
    for k in range(branch_off - 1, max(0, branch_off - 0x800), -1):
        if data[k : k + 4] == b'\xf3\x0f\x1e\xfa':
            fn_add = k
            break
    print(f"  [7] Domain::add()           @ 0x{fn_add:x}")

    # 8. Callers of Domain::add() → addActivated()
    callers = find_calls_to(data, fn_add)
    if not callers:
        raise ValueError("No callers of Domain::add() found")
    print(f"  [8] addActivated() call     @ 0x{callers[0]:x}")

    # 9. CALL just before call-to-add → call to maxAccounts()
    maxacc_call = None
    for k in range(callers[0] - 1, max(0, callers[0] - 0x80), -1):
        if data[k] == 0xE8:
            maxacc_call = k
            break
    if maxacc_call is None:
        raise ValueError("CALL to maxAccounts() not found before CALL to add()")
    fn_maxacc = maxacc_call + 5 + i32(data, maxacc_call + 1)
    print(f"  [9] maxAccounts()           @ 0x{fn_maxacc:x}")

    # 10. Parse maxAccounts(): find  LEA/ADD [reg+kMaxAccounts]  then  MOV kPremiumMaxAccounts
    fn = data[fn_maxacc : fn_maxacc + 0x200]
    found = []
    for i in range(len(fn) - 10):
        lea_imm = lea_len = None
        b = fn[i]
        # 41 8D ?? 24 imm8  (r12-r15 with SIB)
        if b == 0x41 and fn[i+1] == 0x8D and fn[i+3] == 0x24:
            lea_imm, lea_len = fn[i+4], 5
        # 8D [40-7F excluding rm=4] imm8  (rax-rdi, mod=01, no SIB)
        elif b == 0x8D and (fn[i+1] & 0xC0) == 0x40 and (fn[i+1] & 0x07) != 0x04:
            lea_imm, lea_len = fn[i+2], 3
        # 83 [C0-C7] imm8  (ADD reg, imm8)
        elif b == 0x83 and (fn[i+1] & 0xF8) == 0xC0:
            lea_imm, lea_len = fn[i+2], 3
        # 41 83 [C0-C7] imm8  (ADD r8-r15, imm8)
        elif b == 0x41 and fn[i+1] == 0x83 and (fn[i+2] & 0xF8) == 0xC0:
            lea_imm, lea_len = fn[i+3], 4

        if lea_imm is not None and 1 <= lea_imm <= 10:
            nxt = i + lea_len
            if 0xB8 <= fn[nxt] <= 0xBF:      # MOV e?x, imm32
                mov_imm = u32(fn, nxt + 1)
                if 1 <= mov_imm <= 10:
                    found.append((fn_maxacc + i, lea_imm, fn_maxacc + nxt, mov_imm))

    if not found:
        raise ValueError("kMaxAccounts+kPremiumMaxAccounts pattern not found in maxAccounts()")
    lea_addr, old_kmax, mov_addr, old_kprem2 = min(found, key=lambda x: x[1])
    print(f"  [10] kMaxAccounts           @ 0x{lea_addr:x}  (={old_kmax})")
    print(f"       kPremiumMaxAccounts    @ 0x{mov_addr:x}  (={old_kprem2})")

    # Locate the immediate byte inside the LEA/ADD instruction
    lea_imm_off = lea_addr + (5 if data[lea_addr] == 0x41 else 3) - 1
    if data[lea_imm_off] != old_kmax:
        lea_imm_off += 1   # REX-prefixed ADD shifts by one
    patches[lea_imm_off] = (
        bytes([old_kmax]), bytes([NEW_KMAX]),
        f"kMaxAccounts {old_kmax}→{NEW_KMAX}")

    patches[mov_addr + 1] = (
        bytes([old_kprem2]), bytes([NEW_KPREM]),
        f"kPremiumMaxAccounts {old_kprem2}→{NEW_KPREM}")

    # 11. Early-return when accounts list is empty: MOV eax, kMaxAccounts
    early = bytes([0xB8, old_kmax, 0x00, 0x00, 0x00])
    rel = fn.find(early)
    if rel >= 0:
        er_off = fn_maxacc + rel + 1
        patches[er_off] = (bytes([old_kmax]), bytes([NEW_KMAX]),
                           f"kMaxAccounts {old_kmax}→{NEW_KMAX} (empty-list fast path)")
        print(f"  [11] Early-return fast path @ 0x{fn_maxacc + rel:x}")
    else:
        print(f"  [11] Early-return fast path  not found (optimised out — OK)")

    return patches

# ── write patches ────────────────────────────────────────────────────────────

def apply_patches(path, patches, dry_run):
    tag = "DRY RUN" if dry_run else "Patching"
    print(f"\n{tag}: {len(patches)} site(s) in {path}\n")
    with open(path, "rb" if dry_run else "r+b") as f:
        for off in sorted(patches):
            old_b, new_b, desc = patches[off]
            f.seek(off)
            cur = f.read(len(old_b))
            if cur != old_b:
                raise ValueError(
                    f"MISMATCH at 0x{off:x}\n"
                    f"  expected : {old_b.hex()}\n"
                    f"  got      : {cur.hex()}\n"
                    f"  ({desc})")
            if not dry_run:
                f.seek(off); f.write(new_b)
            label = "[dry]" if dry_run else "[OK] "
            print(f"  {label} 0x{off:x}  {old_b.hex()} → {new_b.hex()}")
            print(f"         {desc}")

# ── entry point ──────────────────────────────────────────────────────────────

def main():
    global NEW_KMAX, NEW_KPREM
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Find patches but don't write anything")
    ap.add_argument("--binary",
                    help="Path to Telegram binary (auto-detected if omitted)")
    ap.add_argument("--max", type=int, default=NEW_KMAX, metavar="N",
                    help=f"kMaxAccounts (default {NEW_KMAX}, original 3, max 127)")
    ap.add_argument("--premium-max", type=int, default=NEW_KPREM, metavar="N",
                    help=f"kPremiumMaxAccounts (default {NEW_KPREM}, original 6, max 127)")
    args = ap.parse_args()

    NEW_KMAX  = args.max
    NEW_KPREM = args.premium_max
    if not (1 <= NEW_KMAX <= 127) or not (1 <= NEW_KPREM <= 127):
        sys.exit("Values must be between 1 and 127")

    path = args.binary
    if not path:
        for c in CANDIDATES:
            if os.path.exists(c):
                path = c; break
    if not path:
        sys.exit("Telegram binary not found — use --binary PATH")

    print(f"Binary : {path}")
    print(f"Size   : {os.path.getsize(path):,} bytes")
    print(f"Limits : kMaxAccounts={NEW_KMAX}, kPremiumMaxAccounts={NEW_KPREM}\n")

    print("Loading binary…")
    with open(path, "rb") as f:
        data = f.read()

    print("Searching for patch sites…")
    patches = find_patches(data)

    if not args.dry_run:
        backup = path + ".orig"
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
            print(f"\nBackup → {backup}")
        else:
            print(f"\nBackup already exists: {backup}")

    apply_patches(path, patches, dry_run=args.dry_run)

    if not args.dry_run:
        print(f"\nDone. Restart Telegram.")

if __name__ == "__main__":
    main()
