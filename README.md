# Telegram Account Limit Patcher

Binary patch for Telegram Desktop (flatpak) that removes the account limit.

**Default:** increases `kMaxAccounts` 3→99 and `kPremiumMaxAccounts` 6→99.

## Requirements

- Python 3 + GCC (`sudo pacman -S gcc` / `sudo apt install gcc`)
- Telegram Desktop installed as flatpak

## Usage

```bash
# Patch to 99 accounts (default)
python3 patch_telegram_accounts.py

# Custom limits
python3 patch_telegram_accounts.py --max 33 --premium-max 36

# Check what will be patched without writing
python3 patch_telegram_accounts.py --dry-run
```

Then restart Telegram.

## After a Telegram update

Just run the script again — it finds patch locations dynamically, not by hardcoded offsets.  
A backup of the original binary is saved as `Telegram.orig` next to the binary on the first run.

## How it works

Telegram's `Domain` class has two compile-time constants:

```cpp
static constexpr auto kMaxAccounts        = 3;  // → patched to 99
static constexpr auto kPremiumMaxAccounts = 6;  // → patched to 99
```

The script locates them at runtime by tracing a chain of references:

1. Finds the assertion string `"_accounts.size() < kPremiumMaxAccounts"` in the binary
2. Follows it to the cold (failure) path of `Domain::add()`
3. Finds the conditional jump into that cold path → locates the `CMP` instruction with the account limit
4. Finds the caller of `Domain::add()` → locates `maxAccounts()` via the preceding `CALL`
5. In `maxAccounts()`, patches `LEA [reg+kMaxAccounts]` and `MOV kPremiumMaxAccounts`

## Limits

- Values must be ≤ 127 (fit in a signed 8-bit immediate)
- Telegram's UI may behave oddly with very large numbers of accounts
