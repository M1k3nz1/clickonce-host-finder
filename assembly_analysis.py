from __future__ import annotations

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import pefile

ASM_NS = "{urn:schemas-microsoft-com:asm.v1}"

COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000
RT_MANIFEST = 24


@dataclass
class AssemblyReport:
    path: str
    name: str = ""
    version: str = ""
    architecture: str = ""
    authenticode_signed: bool = False
    cert_subject: str = ""
    cert_issuer: str = ""
    strong_named: bool = False
    public_key_token: str = ""
    mixed_mode: bool = False
    embedded_manifest: bool = False
    uac_level: str = ""
    manifest_processor_arch: str = ""
    manifest_arch_wildcard: bool = False
    signed_manifest_profile: bool = False
    clickonce_status: str = ""
    clickonce_notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _get_dotnet_cor_flags(pe: pefile.PE) -> Optional[int]:
    try:
        clr_entry = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[clr_entry]
        if clr_dir.VirtualAddress == 0 or clr_dir.Size == 0:
            return None
        return pe.get_dword_from_offset(
            pe.get_offset_from_rva(clr_dir.VirtualAddress) + 16
        )
    except Exception:
        return None


def _enumerate_manifest_resource_ids(exe_path: Path) -> list[tuple[int, int]]:
    manifest_entries: list[tuple[int, int]] = []
    pe = None
    try:
        pe = pefile.PE(str(exe_path))
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return manifest_entries
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.id != RT_MANIFEST:
                continue
            for resource_id in resource_type.directory.entries:
                for lang in resource_id.directory.entries:
                    manifest_entries.append((resource_id.id, lang.id))
    except Exception:
        return manifest_entries
    finally:
        if pe is not None:
            pe.close()
    return manifest_entries


def get_dotnet_assembly_identity(exe_path: Path) -> Optional[dict[str, Any]]:
    if sys.platform != "win32":
        return None

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$an = [System.Reflection.AssemblyName]::GetAssemblyName('{exe_path.resolve()}')
$pkt = if ($an.GetPublicKeyToken()) {{
  [BitConverter]::ToString($an.GetPublicKeyToken()).Replace('-', '').ToLower()
}} else {{
  ''
}}
$arch = switch ($an.ProcessorArchitecture) {{
  'MSIL' {{ 'msil' }}
  'X86' {{ 'x86' }}
  'Amd64' {{ 'amd64' }}
  'Arm' {{ 'arm' }}
  'Arm64' {{ 'arm64' }}
  default {{ 'msil' }}
}}
@{{
  Name = $an.Name
  Version = $an.Version.ToString()
  PublicKeyToken = $pkt
  ProcessorArchitecture = $arch
}} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout.strip())
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
        return None


def detect_processor_architecture(exe_path: Path) -> Optional[str]:
    pe = None
    try:
        pe = pefile.PE(str(exe_path))
        machine = pe.FILE_HEADER.Machine
        arch_map = {
            0x8664: "amd64",
            0x200: "ia64",
            0x1c0: "arm",
            0xaa64: "arm64",
        }
        if machine in arch_map:
            return arch_map[machine]
        if machine == 0x14c:
            cor_flags = _get_dotnet_cor_flags(pe)
            if cor_flags is not None:
                if cor_flags & (
                    COMIMAGE_FLAGS_32BITREQUIRED | COMIMAGE_FLAGS_32BITPREFERRED
                ):
                    return "x86"
                return "msil"
            if pe.OPTIONAL_HEADER.Magic == 0x20b:
                return "amd64"
            return "x86"
        return "msil"
    except Exception:
        return None
    finally:
        if pe is not None:
            pe.close()


def is_mixed_mode_assembly(exe_path: Path) -> bool:
    pe = None
    try:
        pe = pefile.PE(str(exe_path))
        cor_flags = _get_dotnet_cor_flags(pe)
        if cor_flags is None:
            return False
        return not bool(cor_flags & COMIMAGE_FLAGS_ILONLY)
    except Exception:
        return False
    finally:
        if pe is not None:
            pe.close()


def _read_embedded_manifest_xml(exe_path: Path) -> Optional[str]:
    pe = None
    try:
        pe = pefile.PE(str(exe_path))
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.id != RT_MANIFEST:
                continue
            for resource_id in resource_type.directory.entries:
                for lang in resource_id.directory.entries:
                    data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                    return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    finally:
        if pe is not None:
            pe.close()
    return None


def _parse_manifest_identity(manifest_xml: Optional[str]) -> tuple[str, bool]:
    if not manifest_xml:
        return "", False
    wildcard = (
        'processorArchitecture="*"' in manifest_xml
        or "processorArchitecture='*'" in manifest_xml
    )
    processor_arch = ""
    try:
        root = ET.fromstring(manifest_xml)
        for node in root.iter(f"{ASM_NS}assemblyIdentity"):
            processor_arch = node.attrib.get("processorArchitecture", "")
            break
        if not processor_arch:
            for node in root.iter("assemblyIdentity"):
                processor_arch = node.attrib.get("processorArchitecture", "")
                break
    except ET.ParseError:
        match = re.search(r'processorArchitecture="([^"]+)"', manifest_xml or "")
        if match:
            processor_arch = match.group(1)
    return processor_arch, wildcard


def _get_uac_level(manifest_xml: Optional[str]) -> str:
    if not manifest_xml:
        return "No UAC settings"
    try:
        root = ET.fromstring(manifest_xml)
        for node in root.iter(f"{ASM_NS}requestedExecutionLevel"):
            return node.attrib.get("level", node.text or "") or "No UAC settings"
        for node in root.iter("requestedExecutionLevel"):
            return node.attrib.get("level", node.text or "") or "No UAC settings"
    except ET.ParseError:
        match = re.search(r'<requestedExecutionLevel[^>]*level="([^"]+)"', manifest_xml)
        if match:
            return match.group(1)
    return "No UAC settings"


def _get_authenticode_signature(exe_path: Path) -> tuple[bool, str, str]:
    if sys.platform != "win32":
        return False, "", ""

    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$sig = Get-AuthenticodeSignature -FilePath '{exe_path.resolve()}'
if ($sig -and $sig.SignerCertificate) {{
  @{{
    Valid = ($sig.Status -eq 'Valid')
    Subject = $sig.SignerCertificate.Subject
    Issuer = $sig.SignerCertificate.Issuer
  }} | ConvertTo-Json -Compress
}} else {{
  @{{ Valid = $false; Subject = ''; Issuer = '' }} | ConvertTo-Json -Compress
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout.strip() or "{}")
        return (
            bool(payload.get("Valid")),
            str(payload.get("Subject") or ""),
            str(payload.get("Issuer") or ""),
        )
    except Exception:
        return False, "", ""


def matches_signed_manifest_profile(
    *,
    authenticode_signed: bool,
    uac_level: str,
    manifest_xml: Optional[str],
) -> bool:
    """Signed binary with asInvoker (or no UAC) and processorArchitecture in embedded manifest."""
    if not authenticode_signed:
        return False
    if uac_level not in {"asInvoker", "No UAC settings"}:
        return False
    if not manifest_xml:
        return False
    return "processorArchitecture" in manifest_xml


def classify_clickonce_compatibility(
    *,
    strong_named: bool,
    mixed_mode: bool,
    embedded_manifest: bool,
    manifest_arch_wildcard: bool,
    signed_manifest_profile: bool,
) -> tuple[str, str]:
    if mixed_mode and strong_named:
        return (
            "incompatible",
            "Strong-named mixed-mode (C++/CLI) assembly; cannot strip manifest or neutralize",
        )
    if manifest_arch_wildcard and embedded_manifest:
        return (
            "incompatible",
            "Embedded manifest uses processorArchitecture='*', which breaks ClickOnce parsing",
        )
    if not strong_named and not mixed_mode and not embedded_manifest:
        return "ready", "Weak-named pure IL without embedded manifest"
    if not strong_named and not mixed_mode and embedded_manifest:
        return "ready", "Weak-named pure IL; embedded manifest can be stripped before packaging"
    if strong_named and not mixed_mode:
        return (
            "neutralizable",
            "Strong-named pure IL; can be neutralized via ildasm/ilasm before packaging",
        )
    if signed_manifest_profile and mixed_mode:
        return (
            "incompatible",
            "Passes signed-manifest profile but is mixed-mode like FileHistory.exe",
        )
    return "unknown", "Manual review recommended"


def analyze_assembly(exe_path: Path) -> Optional[AssemblyReport]:
    exe_path = exe_path.resolve()
    if not exe_path.is_file() or exe_path.suffix.lower() != ".exe":
        return None

    identity = get_dotnet_assembly_identity(exe_path)
    if identity is None:
        return None

    architecture = detect_processor_architecture(exe_path) or identity.get(
        "ProcessorArchitecture", ""
    )
    public_key_token = identity.get("PublicKeyToken") or ""
    strong_named = bool(public_key_token)
    mixed_mode = is_mixed_mode_assembly(exe_path)
    embedded_manifest = bool(_enumerate_manifest_resource_ids(exe_path))
    manifest_xml = _read_embedded_manifest_xml(exe_path) if embedded_manifest else None
    manifest_processor_arch, manifest_arch_wildcard = _parse_manifest_identity(manifest_xml)
    uac_level = _get_uac_level(manifest_xml)
    signed, cert_subject, cert_issuer = _get_authenticode_signature(exe_path)
    manifest_profile = matches_signed_manifest_profile(
        authenticode_signed=signed,
        uac_level=uac_level,
        manifest_xml=manifest_xml,
    )
    clickonce_status, clickonce_notes = classify_clickonce_compatibility(
        strong_named=strong_named,
        mixed_mode=mixed_mode,
        embedded_manifest=embedded_manifest,
        manifest_arch_wildcard=manifest_arch_wildcard,
        signed_manifest_profile=manifest_profile,
    )

    return AssemblyReport(
        path=str(exe_path),
        name=identity.get("Name", exe_path.stem),
        version=identity.get("Version", ""),
        architecture=architecture or "",
        authenticode_signed=signed,
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        strong_named=strong_named,
        public_key_token=public_key_token,
        mixed_mode=mixed_mode,
        embedded_manifest=embedded_manifest,
        uac_level=uac_level,
        manifest_processor_arch=manifest_processor_arch,
        manifest_arch_wildcard=manifest_arch_wildcard,
        signed_manifest_profile=manifest_profile,
        clickonce_status=clickonce_status,
        clickonce_notes=clickonce_notes,
    )
