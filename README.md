# ClickOnce Host Finder

Discover and rank .NET executables on Windows for ClickOnce host suitability. Scores x86/x64
binaries by Authenticode signing, strong-name/mixed-mode status, and embedded manifest
compatibility.

Pairs with the [ClickOnce Payload Generator](https://github.com/Malcrove/clickonce-generator) for
AppDomainManager injection workflows.

---

## Requirements

- Windows
- Python 3.9+

---

## Installation

```bash
git clone <your-repo-url>
cd clickonce-host-finder
pip install -r requirements.txt
```

---

## Usage

Built-in scan (no external tools required):

```bash
python find_clickonce_hosts.py --path "C:\Program Files" --clickonce-ready-only
```

With an optional external .NET discovery tool (`key=value` CLI that prints `[+] Found assembly: <path>`):

```bash
python find_clickonce_hosts.py \
  --discovery-tool "C:\path\to\DiscoveryTool.exe" \
  --path "C:\Program Files" \
  --path "C:\Windows" \
  --services \
  --tasks
```

### Filters

```bash
# 64-bit, Authenticode-signed, signed-manifest profile matches
python find_clickonce_hosts.py --arch x64 --signed-only --signed-manifest-profile-only

# 32-bit unsigned candidates
python find_clickonce_hosts.py --arch x86 --unsigned-only

# Show why FileHistory.exe is incompatible
python find_clickonce_hosts.py --path "C:\Windows\System32\FileHistory.exe" --include-incompatible

# Export JSON
python find_clickonce_hosts.py --path "C:\Program Files" --format json -o candidates.json
```

### CLI options

| Flag | Description |
|------|-------------|
| `--path` | Directory or file to scan (repeatable) |
| `--discovery-tool` | Optional external .NET enumeration executable |
| `--services` / `--tasks` / `--autoruns` | Extended scans (require `--discovery-tool`) |
| `--arch x86\|x64\|msil\|any` | Architecture filter |
| `--signed-only` / `--unsigned-only` | Authenticode filter |
| `--signed-manifest-profile-only` | Signed + asInvoker + embedded `processorArchitecture` |
| `--clickonce-ready-only` | `ready` or `neutralizable` status only |
| `--include-incompatible` | Include binaries like FileHistory.exe |
| `--format table\|json\|csv` | Output format |
| `-o` / `--output` | Write results to file |

---

## Compatibility scoring

Each result includes a `clickonce_status`:

| Status | Meaning |
|--------|---------|
| `ready` | Weak-named pure IL; usable directly as a ClickOnce host |
| `neutralizable` | Strong-named pure IL; can be stripped/neutralized before packaging |
| `incompatible` | Mixed-mode, wildcard manifest, or otherwise unusable |
| `unknown` | Review manually |

`signed_manifest_profile=yes` means the binary is Authenticode-signed, runs at `asInvoker` (or has
no UAC manifest), and its embedded manifest declares `processorArchitecture`. That profile alone
does not guarantee ClickOnce compatibility.

---
