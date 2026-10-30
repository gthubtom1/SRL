#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK metadata contracts without Java or third-party parsers.

The old ``seep_apk_info`` implementation treated every ``META-INF/*`` file as
a signing certificate and searched binary AndroidManifest.xml as if it were
ASCII text.  Both operations produced confident false evidence.  This module
parses the Android binary XML string/element tables and separates signing
artifacts from arbitrary archive metadata.

The module has no import-time IO and intentionally does not depend on
androguard.  Malformed manifests return an explicit error object; callers
must not turn that error into "there are no manifest markers".
"""

from __future__ import annotations

import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
from lib import process_tree

ANDROID_NS = "http://schemas.android.com/apk/res/android"

_XML_TYPE = 0x0003
_STRING_POOL_TYPE = 0x0001
_START_ELEMENT_TYPE = 0x0102
_RES_STRING_POOL_UTF8 = 0x00000100
_NO_INDEX = 0xFFFFFFFF
_APK_SIG_MAGIC = b"APK Sig Block 42"

_TYPE_REFERENCE = 0x01
_TYPE_ATTRIBUTE = 0x02
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_BOOLEAN = 0x12

_V2_SCHEME_ID = 0x7109871A
_V3_SCHEME_ID = 0xF05368C0
_V31_SCHEME_ID = 0x1B93AD61

_COMPONENT_TAGS = {
    "activity": "activities",
    "activity-alias": "activity_aliases",
    "service": "services",
    "receiver": "receivers",
    "provider": "providers",
}
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024


class AXmlError(ValueError):
    """Raised when a binary AndroidManifest.xml is structurally invalid."""


def run_command(command: list[str], cwd: str | None = None,
                timeout: int = 60) -> dict[str, Any]:
    """Run a command while preserving rc/stdout/stderr as separate facts."""
    started = time.monotonic()
    effective = list(command)
    run = process_tree.run
    if (os.name == "nt" and effective
            and effective[0].lower().endswith((".bat", ".cmd"))):
        # Reuse the batch boundary that quotes via environment expansion;
        # list2cmdline alone does not escape cmd's &, %, ! or redirections.
        from tool_autodiscover import _run_tool_process as run
    try:
        proc = run(
            effective,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        )
        return {
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except (OSError, ValueError) as exc:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "duration_seconds": round(time.monotonic() - started, 3),
        }


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AXmlError("truncated uint16 at offset %d" % offset)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AXmlError("truncated uint32 at offset %d" % offset)
    return struct.unpack_from("<I", data, offset)[0]


def _utf8_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode Android's one- or two-byte UTF-8 string length prefix."""
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= len(data):
            raise AXmlError("truncated UTF-8 length")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _decode_string_pool(data: bytes, offset: int) -> list[str]:
    if _u16(data, offset) != _STRING_POOL_TYPE:
        raise AXmlError("string pool chunk missing")
    header_size = _u16(data, offset + 2)
    chunk_size = _u32(data, offset + 4)
    end = offset + chunk_size
    if header_size < 28 or chunk_size < header_size or end > len(data):
        raise AXmlError("invalid string pool bounds")

    string_count = _u32(data, offset + 8)
    flags = _u32(data, offset + 16)
    strings_start = _u32(data, offset + 20)
    offsets_end = offset + header_size + string_count * 4
    strings_base = offset + strings_start
    if offsets_end > end or strings_base > end:
        raise AXmlError("string pool offsets out of bounds")

    utf8 = bool(flags & _RES_STRING_POOL_UTF8)
    values: list[str] = []
    for index in range(string_count):
        string_offset = _u32(data, offset + header_size + index * 4)
        pos = strings_base + string_offset
        if pos >= end:
            raise AXmlError("string %d starts outside pool" % index)
        if utf8:
            _char_length, pos = _utf8_length(data, pos)
            byte_length, pos = _utf8_length(data, pos)
            if pos + byte_length > end:
                raise AXmlError("string %d extends outside pool" % index)
            values.append(data[pos:pos + byte_length].decode("utf-8", "replace"))
        else:
            char_length = _u16(data, pos)
            pos += 2
            if char_length & 0x8000:
                char_length = ((char_length & 0x7FFF) << 16) | _u16(data, pos)
                pos += 2
            byte_length = char_length * 2
            if pos + byte_length > end:
                raise AXmlError("UTF-16 string %d extends outside pool" % index)
            values.append(data[pos:pos + byte_length].decode("utf-16le", "replace"))
    return values


def _string_at(strings: list[str], index: int) -> str | None:
    return None if index == _NO_INDEX or index >= len(strings) else strings[index]


def _typed_value(data_type: int, value: int, strings: list[str],
                 raw_index: int) -> Any:
    if data_type == _TYPE_STRING:
        return _string_at(strings, value)
    if data_type in (_TYPE_INT_DEC, _TYPE_INT_HEX):
        return struct.unpack("<i", struct.pack("<I", value))[0]
    if data_type == _TYPE_BOOLEAN:
        return bool(value)
    if data_type == _TYPE_REFERENCE:
        return "@0x%08x" % value
    if data_type == _TYPE_ATTRIBUTE:
        return "?0x%08x" % value
    if data_type == _TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", value))[0]
    return _string_at(strings, raw_index)


def _attribute_name(namespace: str | None, name: str | None) -> str:
    if not name:
        return ""
    if namespace == ANDROID_NS:
        return "android:" + name
    if namespace:
        return "{%s}%s" % (namespace, name)
    return name


def _append_unique(container: list, value: Any) -> None:
    if value is not None and value not in container:
        container.append(value)


def parse_binary_manifest(raw: bytes) -> dict[str, Any]:
    """Parse the subset of Android binary XML needed for manifest facts."""
    if len(raw) < 8 or _u16(raw, 0) != _XML_TYPE:
        raise AXmlError("not Android binary XML (RES_XML_TYPE missing)")
    root_header_size = _u16(raw, 2)
    root_size = _u32(raw, 4)
    if root_header_size < 8 or root_size < root_header_size or root_size > len(raw):
        raise AXmlError("invalid binary XML root bounds")

    strings: list[str] = []
    pos = root_header_size
    end = root_size
    result: dict[str, Any] = {
        "status": "ok",
        "format": "binary",
        "package": None,
        "version_code": None,
        "version_name": None,
        "uses_permissions": [],
        "declared_permissions": [],
        "uses_features": [],
        "min_sdk_version": None,
        "target_sdk_version": None,
        "activities": [],
        "activity_aliases": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "application_name": None,
        "debuggable": None,
        "allow_backup": None,
        "element_count": 0,
    }

    while pos + 8 <= end:
        chunk_type = _u16(raw, pos)
        header_size = _u16(raw, pos + 2)
        chunk_size = _u32(raw, pos + 4)
        if header_size < 8 or chunk_size < header_size or pos + chunk_size > end:
            raise AXmlError("invalid chunk bounds at offset %d" % pos)

        if chunk_type == _STRING_POOL_TYPE:
            strings = _decode_string_pool(raw, pos)
        elif chunk_type == _START_ELEMENT_TYPE:
            if not strings:
                raise AXmlError("start element before string pool")
            ext = pos + 16
            tag = _string_at(strings, _u32(raw, ext + 4))
            attr_start = _u16(raw, ext + 8)
            attr_size = _u16(raw, ext + 10)
            attr_count = _u16(raw, ext + 12)
            if attr_size < 20:
                raise AXmlError("attribute record smaller than 20 bytes")
            attr_pos = ext + attr_start
            attrs: dict[str, Any] = {}
            for _ in range(attr_count):
                if attr_pos + attr_size > pos + chunk_size:
                    raise AXmlError("attribute extends outside start element")
                attr_ns = _string_at(strings, _u32(raw, attr_pos))
                attr_name = _string_at(strings, _u32(raw, attr_pos + 4))
                raw_value = _u32(raw, attr_pos + 8)
                data_type = raw[attr_pos + 15]
                data_value = _u32(raw, attr_pos + 16)
                key = _attribute_name(attr_ns, attr_name)
                if key:
                    attrs[key] = _typed_value(data_type, data_value, strings, raw_value)
                attr_pos += attr_size

            result["element_count"] += 1
            if tag == "manifest":
                result["package"] = attrs.get("package")
                result["version_code"] = attrs.get("android:versionCode")
                result["version_name"] = attrs.get("android:versionName")
            elif tag == "uses-permission":
                _append_unique(result["uses_permissions"], attrs.get("android:name"))
            elif tag == "permission":
                _append_unique(
                    result["declared_permissions"], attrs.get("android:name"))
            elif tag == "uses-sdk":
                result["min_sdk_version"] = attrs.get("android:minSdkVersion")
                result["target_sdk_version"] = attrs.get("android:targetSdkVersion")
            elif tag == "uses-feature":
                feature = {"name": attrs.get("android:name")}
                if "android:required" in attrs:
                    feature["required"] = attrs["android:required"]
                if feature["name"] is not None:
                    result["uses_features"].append(feature)
            elif tag == "application":
                result["application_name"] = attrs.get("android:name")
                result["debuggable"] = attrs.get("android:debuggable")
                result["allow_backup"] = attrs.get("android:allowBackup")
            elif tag in _COMPONENT_TAGS:
                name = attrs.get("android:name")
                if name is not None:
                    component = {"name": name}
                    if "android:exported" in attrs:
                        component["exported"] = attrs["android:exported"]
                    if "android:permission" in attrs:
                        component["permission"] = attrs["android:permission"]
                    result[_COMPONENT_TAGS[tag]].append(component)
        pos += chunk_size

    if pos != end:
        raise AXmlError("binary XML ended mid-chunk")
    if result["element_count"] == 0:
        raise AXmlError("binary XML contains no start elements")
    return result


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_attr(element: ET.Element, name: str) -> Any:
    value = element.attrib.get("{%s}%s" % (ANDROID_NS, name))
    if value is not None:
        if value in ("true", "false"):
            return value == "true"
        return value
    return element.attrib.get(name)


def parse_text_manifest(raw: bytes) -> dict[str, Any]:
    """Parse a plain XML manifest used by tests and uncommon tooling."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AXmlError("plain XML parse failed: %s" % exc) from exc
    version_code = _xml_attr(root, "versionCode")
    if isinstance(version_code, str) and re.fullmatch(r"-?\d+", version_code):
        version_code = int(version_code)
    result: dict[str, Any] = {
        "status": "ok",
        "format": "text",
        "package": root.attrib.get("package"),
        "version_code": version_code,
        "version_name": _xml_attr(root, "versionName"),
        "uses_permissions": [],
        "declared_permissions": [],
        "uses_features": [],
        "min_sdk_version": None,
        "target_sdk_version": None,
        "activities": [],
        "activity_aliases": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "application_name": None,
        "debuggable": None,
        "allow_backup": None,
        "element_count": sum(1 for _ in root.iter()),
    }
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag == "uses-permission":
            _append_unique(result["uses_permissions"], _xml_attr(element, "name"))
        elif tag == "permission":
            _append_unique(result["declared_permissions"], _xml_attr(element, "name"))
        elif tag == "uses-sdk":
            result["min_sdk_version"] = _xml_attr(element, "minSdkVersion")
            result["target_sdk_version"] = _xml_attr(element, "targetSdkVersion")
        elif tag == "uses-feature":
            name = _xml_attr(element, "name")
            if name is not None:
                feature = {"name": name}
                required = _xml_attr(element, "required")
                if required is not None:
                    feature["required"] = required
                result["uses_features"].append(feature)
        elif tag == "application":
            result["application_name"] = _xml_attr(element, "name")
            result["debuggable"] = _xml_attr(element, "debuggable")
            result["allow_backup"] = _xml_attr(element, "allowBackup")
        elif tag in _COMPONENT_TAGS:
            name = _xml_attr(element, "name")
            if name is not None:
                component = {"name": name}
                exported = _xml_attr(element, "exported")
                permission = _xml_attr(element, "permission")
                if exported is not None:
                    component["exported"] = exported
                if permission is not None:
                    component["permission"] = permission
                result[_COMPONENT_TAGS[tag]].append(component)
    return result


def parse_manifest(raw: bytes) -> dict[str, Any]:
    """Return parsed facts or a structured parse error, never silent emptiness."""
    try:
        stripped = raw.lstrip()
        if stripped.startswith(b"<"):
            return parse_text_manifest(stripped)
        return parse_binary_manifest(raw)
    except (AXmlError, UnicodeError, struct.error, ValueError) as exc:
        return {
            "status": "error",
            "format": "unknown",
            "error": type(exc).__name__,
            "detail": str(exc)[:300],
        }


def _signing_block_scheme_ids(path: str) -> list[int]:
    """Read APK Signing Block pair IDs without loading the whole APK."""
    file_size = os.path.getsize(path)
    if file_size < 32:
        return []
    with open(path, "rb") as fh:
        tail_size = min(file_size, 65557)
        fh.seek(file_size - tail_size)
        tail = fh.read()
        eocd_index = -1
        search_end = len(tail)
        while search_end:
            candidate = tail.rfind(b"PK\x05\x06", 0, search_end)
            if candidate < 0:
                break
            if candidate + 22 <= len(tail):
                comment_size = struct.unpack_from("<H", tail, candidate + 20)[0]
                if candidate + 22 + comment_size == len(tail):
                    eocd_index = candidate
                    break
            search_end = candidate
        if eocd_index < 0:
            return []
        cd_offset = struct.unpack_from("<I", tail, eocd_index + 16)[0]
        if cd_offset < 24 or cd_offset > file_size:
            return []
        fh.seek(cd_offset - 24)
        footer = fh.read(24)
        if len(footer) != 24 or footer[8:] != _APK_SIG_MAGIC:
            return []
        block_size = struct.unpack_from("<Q", footer, 0)[0]
        block_start = cd_offset - block_size - 8
        if block_start < 0 or block_start + block_size + 8 != cd_offset:
            return []
        # The first uint64 is the same size and lives immediately before the
        # pair sequence at block_start.
        fh.seek(block_start)
        prefix = fh.read(8)
        if len(prefix) != 8 or struct.unpack("<Q", prefix)[0] != block_size:
            return []
        pair_offset = block_start + 8
        pair_end = cd_offset - 24
        ids: list[int] = []
        while pair_offset + 12 <= pair_end:
            fh.seek(pair_offset)
            pair_header = fh.read(12)
            if len(pair_header) != 12:
                return []
            pair_id, value_size = struct.unpack("<QI", pair_header)
            next_offset = pair_offset + 12 + value_size
            if next_offset > pair_end:
                return []
            ids.append(pair_id)
            pair_offset = next_offset
        return ids if pair_offset == pair_end else []


def signing_evidence(path: str, names: list[str]) -> dict[str, Any]:
    """Classify v1 artifacts and detect v2/v3 blocks by their real IDs."""
    meta = [name for name in names if name.startswith("META-INF/")]
    cert_blocks = [
        name for name in meta
        if re.fullmatch(r"META-INF/[^/]+\.(?:RSA|DSA|EC)", name, re.IGNORECASE)
    ]
    signature_files = [
        name for name in meta
        if re.fullmatch(r"META-INF/[^/]+\.SF", name, re.IGNORECASE)
    ]
    scheme_ids = _signing_block_scheme_ids(path)
    schemes: list[str] = []
    if _V2_SCHEME_ID in scheme_ids:
        schemes.append("v2")
    if _V3_SCHEME_ID in scheme_ids:
        schemes.append("v3")
    if _V31_SCHEME_ID in scheme_ids:
        schemes.append("v3.1")
    if cert_blocks:
        schemes.insert(0, "v1")
    return {
        "schemes": list(dict.fromkeys(schemes)),
        "v1_certificate_blocks": cert_blocks,
        "v1_signature_files": signature_files,
        "v1_manifest_present": "META-INF/MANIFEST.MF" in meta,
        "apk_signing_block_present": bool(scheme_ids),
        "signing_block_pair_ids": ["0x%08x" % value for value in scheme_ids],
        "unclassified_meta_inf_files": [
            name for name in meta
            if name not in cert_blocks
            and name not in signature_files
            and name != "META-INF/MANIFEST.MF"
        ],
    }


def jadx_output_evidence(output_dir: str) -> dict[str, Any]:
    """Count real source/resource artifacts instead of treating any file as success."""
    file_count = 0
    java_count = 0
    xml_count = 0
    manifests: list[str] = []
    extensions: dict[str, int] = {}
    for root, _dirs, files in os.walk(output_dir):
        for name in files:
            full = os.path.join(root, name)
            file_count += 1
            ext = os.path.splitext(name)[1].lower() or "<none>"
            extensions[ext] = extensions.get(ext, 0) + 1
            if ext == ".java":
                java_count += 1
            elif ext == ".xml":
                xml_count += 1
            if name == "AndroidManifest.xml":
                manifests.append(os.path.relpath(full, output_dir).replace(os.sep, "/"))
    return {
        "output_dir": os.path.abspath(output_dir),
        "file_count": file_count,
        "java_count": java_count,
        "xml_count": xml_count,
        "manifest_files": manifests,
        "extensions": dict(sorted(extensions.items())),
        "has_expected_artifacts": bool(java_count or manifests or xml_count),
    }


def inspect_apk(path: str) -> dict[str, Any]:
    """Return archive, manifest, and signing facts for one APK."""
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        dex_files = [name for name in names if name.lower().endswith(".dex")]
        shared_objects = [name for name in names if name.lower().endswith(".so")]
        architectures = {
            name.split("/")[1]
            for name in shared_objects
            if name.startswith("lib/") and name.count("/") >= 2
        }
        manifest_entries = [
            info for info in archive.infolist()
            if info.filename == "AndroidManifest.xml"
        ]
        if len(manifest_entries) > 1:
            manifest = {
                "status": "error",
                "format": "unknown",
                "error": "duplicate_manifest",
                "detail": "archive contains multiple AndroidManifest.xml entries",
            }
        elif len(manifest_entries) == 1:
            info = manifest_entries[0]
            if info.file_size > _MAX_MANIFEST_BYTES:
                manifest = {
                    "status": "error",
                    "format": "unknown",
                    "error": "manifest_too_large",
                    "detail": "manifest exceeds %d bytes" % _MAX_MANIFEST_BYTES,
                }
            else:
                manifest = parse_manifest(archive.read(info))
        else:
            manifest = {
                "status": "missing",
                "format": "none",
                "error": "AndroidManifest.xml not present",
                "detail": "archive entry is missing",
            }
    signing = signing_evidence(path, names)
    markers: list[str] = []
    if manifest.get("status") == "ok":
        for value in (
            manifest.get("package"),
            manifest.get("application_name"),
            *manifest.get("uses_permissions", []),
            *[item.get("name") for item in manifest.get("activities", [])],
            *[item.get("name") for item in manifest.get("services", [])],
            *[item.get("name") for item in manifest.get("receivers", [])],
            *[item.get("name") for item in manifest.get("providers", [])],
        ):
            _append_unique(markers, value)
    return {
        "file_size": os.path.getsize(path),
        "dex_count": len(dex_files),
        "dex_files": dex_files,
        "native_architectures": sorted(architectures),
        "native_libraries_count": len(shared_objects),
        "manifest": manifest,
        # Kept for existing consumers, but this field now contains only actual
        # v1 certificate blocks rather than every META-INF entry.
        "signed_certificates": signing["v1_certificate_blocks"][:5],
        "manifest_key_markers": markers[:30],
        "signing": signing,
    }


def _jadx_launch_prefix(java_path: str, jadx_entry: str) -> list[str]:
    """Prefer the bundled JAR so a timeout kills the JVM, not a wrapper shell."""
    entry = os.path.abspath(jadx_entry)
    jadx_root = os.path.dirname(os.path.dirname(entry))
    candidates = sorted(
        os.path.join(jadx_root, "lib", name)
        for name in (os.listdir(os.path.join(jadx_root, "lib"))
                     if os.path.isdir(os.path.join(jadx_root, "lib")) else [])
        if re.fullmatch(r"jadx-.+-all\.jar", name, re.IGNORECASE)
    )
    if java_path and candidates:
        return [
            java_path,
            "-Xms256M",
            "-XX:MaxRAMPercentage=70.0",
            "-Djdk.util.zip.disableZip64ExtraFieldValidation=true",
            "-cp",
            candidates[-1],
            "jadx.cli.JadxCLI",
        ]
    return [jadx_entry]


def run_jadx(java_path: str, jadx_entry: str, apk_path: str,
             output_dir: str, deobfuscate: bool = True,
             timeout: int = 300) -> dict[str, Any]:
    """Run JADX into a staging directory and preserve partial artifacts."""
    output_dir = os.path.abspath(output_dir)
    parent = os.path.dirname(output_dir)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        return {
            "status": "error",
            "error": "output_parent_unavailable",
            "output_dir": output_dir,
            "detail": str(exc),
        }
    if os.path.exists(output_dir) and (
            not os.path.isdir(output_dir) or os.listdir(output_dir)):
        return {
            "status": "error",
            "error": "output_exists",
            "output_dir": output_dir,
            "hint": "choose a new or empty output directory",
        }

    try:
        stage = tempfile.mkdtemp(prefix=".seep-jadx-", dir=parent)
    except OSError as exc:
        return {
            "status": "error",
            "error": "staging_unavailable",
            "output_dir": output_dir,
            "detail": str(exc),
        }
    command = _jadx_launch_prefix(java_path, jadx_entry) + ["-d", stage]
    if deobfuscate:
        command.append("--deobf")
    command.append(os.path.abspath(apk_path))
    execution = run_command(command, timeout=timeout)
    evidence = jadx_output_evidence(stage)
    result: dict[str, Any] = {
        "status": "error",
        "tool": "jadx",
        "command_entry": jadx_entry,
        "java": java_path,
        "returncode": execution["returncode"],
        "timed_out": execution["timed_out"],
        "duration_seconds": execution["duration_seconds"],
        "stdout": execution["stdout"][:4000],
        "stderr": execution["stderr"][:4000],
        "artifacts": evidence,
        "staging_dir": stage,
    }
    if execution["timed_out"]:
        result["error"] = "timeout"
        return result
    if not evidence["has_expected_artifacts"]:
        result["error"] = "no_expected_artifacts"
        return result

    try:
        if os.path.isdir(output_dir):
            os.rmdir(output_dir)
        os.replace(stage, output_dir)
    except OSError as exc:
        result["error"] = "publish_failed"
        result["detail"] = str(exc)
        return result

    published = jadx_output_evidence(output_dir)
    result.update({
        "status": "ok" if execution["returncode"] == 0 else "partial",
        "artifacts": published,
        "output_dir": os.path.abspath(output_dir),
        "staging_dir": None,
        "note": ("JADX exited non-zero but produced source/resource artifacts; "
                 "inspect stderr before relying on the output."),
    })
    if execution["returncode"] == 0:
        result.pop("note")
    return result

