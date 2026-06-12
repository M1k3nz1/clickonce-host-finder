# ClickOnce Host Finder

Discover and rank .NET executables on Windows for ClickOnce host suitability. Scores x86/x64
binaries by Authenticode signing, strong-name/mixed-mode status, and embedded manifest
compatibility.

Use this tool to shortlist host executables before packaging them into ClickOnce deployments with
AppDomainManager injection or similar workflows.

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

## Quick start

Scan a single file (fastest way to inspect a known candidate):

```powershell
python find_clickonce_hosts.py --path "C:\Windows\System32\FileHistory.exe" --include-incompatible
```

Scan a directory with progress on stderr and stop after 10 matches:

```powershell
python find_clickonce_hosts.py --path "C:\Program Files\Contoso" --max-results 10
```

Default roots (when `--path` is omitted) are `C:\Program Files` and `C:\Program Files (x86)`.
Always prefer `--path` on large drives — full-tree scans can take a long time even with filters.

---

## Usage examples

### Narrow scope and watch progress

Progress prints to stderr every 250 executables (`scanned … .NET … match(es)`). Use `--quiet` to hide it.

```powershell
python find_clickonce_hosts.py --path "C:\Windows\System32" --arch x64 --max-results 5
```

### ClickOnce-ready hosts only

Weak-named pure IL, or strong-named pure IL that can be neutralized before packaging:

```powershell
python find_clickonce_hosts.py --path "C:\Program Files" --clickonce-ready-only --max-results 20
```

### Signed 64-bit binaries with the signed-manifest profile

Authenticode-signed, `asInvoker` (or no UAC), and an embedded manifest that declares
`processorArchitecture`:

```powershell
python find_clickonce_hosts.py --path "C:\Windows\System32" --arch x64 --signed-only --signed-manifest-profile-only --max-results 10
```

This profile matches binaries like `FileHistory.exe`, but many hits are still **incompatible**
(mixed-mode, wildcard manifest). Add `--include-incompatible` to see them.

### Win32 manifest `<assemblyIdentity>` filters

Inspect whether the embedded application manifest has an active top-level identity node:

```powershell
# Active top-level <assemblyIdentity> under <assembly>
python find_clickonce_hosts.py --path "C:\Windows\System32\FileHistory.exe" --manifest-top-identity-only --include-incompatible

# Binaries with no active top-level identity (includes apps with no embedded manifest)
python find_clickonce_hosts.py --path "C:\Program Files" --no-manifest-top-identity --max-results 10

# Identity only inside XML comments (<!-- ... assemblyIdentity ... -->)
python find_clickonce_hosts.py --path "C:\Program Files" --manifest-top-identity-commented-only --max-results 10
```

### Architecture and signing

```powershell
# 32-bit unsigned candidates
python find_clickonce_hosts.py --path "C:\Program Files (x86)" --arch x86 --unsigned-only --max-results 15

# Any-architecture, signed only
python find_clickonce_hosts.py --path "C:\Program Files\Vendor" --signed-only --format table
```

### Export results

```powershell
# JSON for scripting
python find_clickonce_hosts.py --path "C:\Program Files" --clickonce-ready-only --format json -o candidates.json

# CSV for spreadsheets
python find_clickonce_hosts.py --path "C:\Program Files" --arch x64 --format csv -o hosts.csv

# JSON to stdout (pipe-friendly)
python find_clickonce_hosts.py --path "C:\Windows\System32\notepad.exe" --format json --quiet
```

### Optional external discovery tool

If you have a separate .NET enumerator that prints `[+] Found assembly: <path>` lines and accepts
`key=value` arguments:

```powershell
python find_clickonce_hosts.py `
  --discovery-tool "C:\tools\DiscoveryTool.exe" `
  --path "C:\Program Files" `
  --path "C:\Windows" `
  --services `
  --tasks `
  --arch x64 `
  --signed-only
```

### Combine filters

```powershell
python find_clickonce_hosts.py `
  --path "C:\Program Files" `
  --arch x64 `
  --signed-only `
  --manifest-top-identity-only `
  --clickonce-ready-only `
  --max-results 5 `
  --format table
```

---

## CLI options

| Flag | Description |
|------|-------------|
| `--path` | Directory or file to scan (repeatable). Omit for default Program Files roots. |
| `--discovery-tool` | Optional external .NET enumeration executable |
| `--services` / `--tasks` / `--autoruns` | Extended scans (require `--discovery-tool`) |
| `--all-paths` | Do not skip common Microsoft-heavy directories during walks |
| `--arch x86\|x64\|msil\|any` | Architecture filter (`x64` matches `amd64`) |
| `--signed-only` / `--unsigned-only` | Authenticode filter |
| `--signed-manifest-profile-only` | Signed + asInvoker + embedded `processorArchitecture` |
| `--manifest-top-identity-only` | Active top-level `<assemblyIdentity>` in embedded Win32 manifest |
| `--manifest-top-identity-commented-only` | `<assemblyIdentity>` only inside `<!-- -->` comments |
| `--no-manifest-top-identity` | No active top-level `<assemblyIdentity>` node |
| `--clickonce-ready-only` | `ready` or `neutralizable` status only |
| `--include-incompatible` | Include binaries like FileHistory.exe |
| `--max-results N` | Stop after N matches (0 = no limit) |
| `--quiet` | Suppress progress messages on stderr |
| `--format table\|json\|csv` | Output format |
| `-o` / `--output` | Write results to file |

---

## Output columns (table format)

| Column | Meaning |
|--------|---------|
| `status` | `ready`, `neutralizable`, `incompatible`, or `unknown` |
| `arch` | PE / .NET architecture (`amd64`, `x86`, `msil`, …) |
| `signed` | Authenticode signature valid |
| `strong` | Strong-named (.NET public key token present) |
| `mixed` | Mixed-mode (C++/CLI) — not pure IL |
| `sig_profile` | Matches signed-manifest profile heuristic |
| `top_id` | Active top-level Win32 manifest `<assemblyIdentity>` |
| `id_comment` | `<assemblyIdentity>` only in XML comments |
| `dep_id` | Count of dependency `<assemblyIdentity>` nodes |
| `name` / `path` | .NET assembly name and file path |
| `notes` | Why the binary is or is not a good ClickOnce host |

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

### Example: FileHistory.exe

`C:\Windows\System32\FileHistory.exe` is a useful reference binary:

- `sig_profile=yes`, `top_id=yes`, `manifest_processor_arch=*`
- `status=incompatible` — strong-named **mixed-mode** assembly; manifest cannot be stripped without
  breaking the signature, and ildasm/ilasm neutralization fails on C++/CLI

```powershell
python find_clickonce_hosts.py --path "C:\Windows\System32\FileHistory.exe" --include-incompatible --format json
```

For production ClickOnce hosts, build a weak-named template instead of repurposing signed system
binaries.

### Win32 manifest vs .NET assembly identity

Two different things are often both called "assembly identity":

| Source | What it is | How this tool reads it |
|--------|------------|------------------------|
| **Embedded Win32 manifest** (`RT_MANIFEST`) | XML with `<assemblyIdentity>` for the app and dependencies | Parsed from the PE resource; no Assembly Viewer needed |
| **.NET CLI metadata** | Assembly name, version, public key token in IL metadata | `name`, `version`, `public_key_token` fields via PowerShell |

Table columns `top_id`, `id_comment`, and `dep_id` refer to the **Win32 manifest** only:

- `top_id` — active top-level `<assemblyIdentity>` under `<assembly>` (not a dependency)
- `id_comment` — `<assemblyIdentity>` text appears inside `<!-- -->` but there is no active top-level node
- `dep_id` — count of `<assemblyIdentity>` nodes under `<dependency>` blocks (e.g. Common Controls)

---

## Performance tips

- **Use `--path`** to limit scope; avoid scanning entire drives without a directory filter.
- **`--max-results`** stops after N **matches**, not after N files scanned. With strict filters you
  may scan many files before the first hit — watch stderr progress.
- **`--quiet`** hides progress; omit it when debugging long scans.
- Native (non-.NET) executables are skipped quickly via a PE header check before PowerShell runs.

---

## Related

- **ClickOnce Payload Generator** — companion toolkit for building ClickOnce deployments with
  AppDomainManager injection (see the parent `clickonce-generator` repository).
