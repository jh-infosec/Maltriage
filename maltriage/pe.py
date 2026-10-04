"""
PE structure: sections, imports, exports, debug data, overlay and signature.

The first extractor to need the random-access phase, and the only one that
takes an optional dependency for parsing rather than for speed. `pefile` is
absent-tolerant: its absence is reported, never silently absorbed.

`certificate_range` is the exception to this module's shape. It reads the
security directory from the header alone, because that is the one data
directory entry holding a file offset rather than an RVA, and `filetype.py`
calls it in phase 1 so the entropy stream can skip a signature it would
otherwise score as a hot region.
"""

from __future__ import annotations
import logging
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import apis
from .base import (ParserUnavailable, RandomAccessExtractor, _share_budget,
                   region_entropy, safe_text)
from .config import config_int, config_list, config_ratio
from .models import mk_finding

log = logging.getLogger(__name__)


# PE

#: Index of the certificate table in the optional header's data directory.
SECURITY_DIRECTORY = 4


def certificate_range(header: bytes, size: int) -> tuple[int, int] | None:
    """Where a PE keeps its Authenticode signature, from the header alone.

    Returns `(offset, length)` as a byte range in the file, or `None` if this
    is not a PE, is truncated, carries no signature, or claims one that cannot
    be believed.

    This is the one data directory entry that holds a *file offset* rather than
    an RVA, which is what makes it readable without the section table - and
    therefore without the random-access phase. `FileTypeExtractor` publishes it
    into `ctx` in phase 1 so the entropy pass, which is phase 2 and cannot
    seek, knows which bytes are the file's own content and which are its
    signature.

    Measured over 291 files of `C:\\Windows\\System32`: signed files produced an
    `entropy_hotspot` six to a hundred times more often than unsigned files of
    the same size, and every signed file under 32 KB produced one. A DER-encoded
    certificate cannot be anything but high entropy, it is not part of the
    mapped image, and it is not the sample's content in the sense that finding
    means. Scoring it as a hot region inside an otherwise quiet file is scoring
    the envelope rather than the letter.

    **Three checks, because a sample controls this field and the range decides
    which bytes are never looked at.** The first draft required only that the
    range end at the end of the file, and a directory rewritten to say
    "offset 64, length everything" silenced the entropy scan over an entire
    packed binary - an exclusion a sample can aim is an evasion, not a
    refinement. So the range must:

    - lie past the last section's raw data. A certificate that overlaps the
      mapped image is not a certificate; this is the same boundary the overlay
      logic already uses, and it is knowable from the section table, which sits
      in the header beside the directory that makes the claim.
    - end exactly at the end of the file, which Authenticode requires and every
      real signed binary honours.
    - be non-empty and start inside the file.

    A range failing any of them is no range, and the entropy pass then scores
    every byte - which is the safe direction to fail in.
    """
    try:
        if header[:2] != b"MZ":
            return None
        pe_at = int.from_bytes(header[0x3C:0x40], "little")
        if not pe_at or header[pe_at:pe_at + 4] != b"PE\x00\x00":
            return None

        section_count = int.from_bytes(header[pe_at + 6:pe_at + 8], "little")
        optional_size = int.from_bytes(header[pe_at + 20:pe_at + 22], "little")
        optional_at = pe_at + 24
        magic = int.from_bytes(header[optional_at:optional_at + 2], "little")
        if magic == 0x10B:      # PE32
            count_at, directories_at = optional_at + 92, optional_at + 96
        elif magic == 0x20B:    # PE32+
            count_at, directories_at = optional_at + 108, optional_at + 112
        else:
            return None

        if int.from_bytes(header[count_at:count_at + 4], "little") <= SECURITY_DIRECTORY:
            return None
        entry_at = directories_at + SECURITY_DIRECTORY * 8
        entry = header[entry_at:entry_at + 8]
        if len(entry) < 8:
            # The header read stopped short of the directory. Say nothing
            # rather than guess: a wrong range excludes real bytes from the
            # scan, which is worse than excluding none.
            return None
        offset = int.from_bytes(entry[:4], "little")
        length = int.from_bytes(entry[4:], "little")
        if offset <= 0 or length <= 0 or offset >= size or offset + length != size:
            return None

        # Where the mapped image stops. A signature begins after it.
        sections_at = optional_at + optional_size
        image_end = 0
        for index in range(section_count):
            at = sections_at + index * 40
            record = header[at:at + 40]
            if len(record) < 40:
                # The section table was cut off by the header read, so the
                # last section's end is unknown and the check cannot be made.
                return None
            raw_size = int.from_bytes(record[16:20], "little")
            raw_pointer = int.from_bytes(record[20:24], "little")
            if raw_size and raw_pointer:
                image_end = max(image_end, raw_pointer + raw_size)
        if offset < image_end:
            return None

        return offset, length
    except (IndexError, ValueError):
        return None



try:  # optional, and staying that way: see architecture.md, "Dependencies"
    import pefile as _pefile

    HAVE_PEFILE = True
except ImportError:
    _pefile = None
    HAVE_PEFILE = False


# Section characteristics, as the format defines them.
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED = 0x00000040
SCN_CNT_UNINITIALIZED = 0x00000080
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

# COFF characteristics.
FILE_DLL = 0x2000
FILE_SYSTEM = 0x1000

SUBSYSTEM_NATIVE = 1
MAGIC_PE32_PLUS = 0x20B

DIRECTORY_IMPORT = 1
# The certificate table's data directory entry holds a file offset rather
# than an RVA, which is the one exception in the table and a standing trap.
DIRECTORY_SECURITY = 4
DIRECTORY_DEBUG = 6

DEBUG_ENTRY_SIZE = 28
DEBUG_TYPE_CODEVIEW = 2
# CodeView record layouts: the path follows a signature, a GUID or offset,
# and an age.
CODEVIEW_PATH_OFFSET = {b"RSDS": 24, b"NB10": 16}

# OBJECT IDENTIFIER 2.5.4.3, id-at-commonName.
CN_OID = bytes.fromhex("0603550403")



def certificate_common_names(blob: bytes, limit: int = 16) -> list[str]:
    """Scan a PKCS#7 certificate blob for X.509 commonName strings.

    This is a scan, not a parse, and the shallowness is the point. It answers
    "whose name is written inside this signature", which is a triage question.
    It refuses to answer "is this signature valid", which is not a question
    v0.2 can answer: that needs a chain, a trust store and a clock, and none
    of those are dependencies this tool has taken.

    So: the blob carries the whole chain, the names returned therefore include
    issuing CAs as well as the signer, the order is the order they appear in
    the file, and none of it is verified. A crafted file can put any string
    here. Treat the result as an attribution hint to check, never as an
    identity to trust.
    """
    names: list[str] = []
    cursor = 0
    while len(names) < limit:
        found = blob.find(CN_OID, cursor)
        if found < 0:
            break
        cursor = found + len(CN_OID)
        if cursor + 2 > len(blob):
            break
        tag, length = blob[cursor], blob[cursor + 1]
        # Short-form lengths only. A CN longer than 127 bytes is not a name
        # worth chasing into multi-byte length decoding.
        if tag not in (0x0C, 0x13, 0x16, 0x1E) or length > 0x7F:
            continue
        raw = blob[cursor + 2: cursor + 2 + length]
        if len(raw) < length:
            break
        try:
            text = safe_text(
                raw.decode("utf-16-be" if tag == 0x1E else "ascii"), 256).strip()
        except (UnicodeDecodeError, ValueError):
            continue
        if text and text not in names:
            names.append(text)
    return names


def _lookup(table, value: int) -> str:
    """Read pefile's two-way enum tables without trusting them to be populated.

    The constant names carry the format's `IMAGE_FILE_MACHINE_` and
    `IMAGE_SUBSYSTEM_` prefixes, which say nothing a reader of a field called
    `machine_label` does not already know, so they come off.
    """
    try:
        label = table[value]
    except (KeyError, IndexError, TypeError):
        return "unknown"
    if not isinstance(label, str):
        return "unknown"
    for prefix in ("IMAGE_FILE_MACHINE_", "IMAGE_SUBSYSTEM_", "IMAGE_DEBUG_TYPE_"):
        if label.startswith(prefix):
            return label[len(prefix):]
    return label


class PEExtractor(RandomAccessExtractor):
    """Portable Executable structure, parsed with pefile.

    The first extractor that could not have been written as a forward pass.
    An import table lives at an RVA that resolves, through the section table,
    to a file offset nobody knows until the section table has been read, so
    this kind opens the sample and addresses it. pefile maps the file with
    `mmap`, and every figure derived here is computed over a bounded region of
    that mapping rather than over a copy of the sample.

    Extraction only. Every list this produces is data; the judgements about
    that data live in `findings`, and the judgements about import *names* are
    not here at all, because the roadmap puts them in v0.4 and a release
    boundary is not a reason to smuggle a heuristic into a parser.

    Directories are parsed one at a time rather than in a single call. On a
    file built to break a parser, an import table that throws should not also
    cost the export table, the debug directory and the TLS callbacks, and this
    is the same isolation the pipeline gives extractors, applied one level
    further in.
    """

    name = "pe"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") == "pe"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        if not HAVE_PEFILE:
            raise ParserUnavailable(
                "pefile is not installed, so this file was identified as a PE "
                "but not parsed; install it with 'pip install pefile'")

        # Both ceilings exist because the input is hostile by assumption.
        # pefile's defaults are generous enough that a crafted export table
        # can keep it busy for a long time on a file that is not large.
        pe = _pefile.PE(
            name=str(path),
            fast_load=True,
            max_symbol_exports=config_int(config, "pe_max_symbol_exports", 4096),
            max_repeated_symbol=config_int(config, "pe_max_repeated_symbol", 64),
        )
        try:
            return self._parse(pe, ctx, config)
        finally:
            pe.close()

    # extraction

    def _parse(self, pe, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        problems: list[str] = []

        def attempt(label, fn, default):
            """Run one piece of extraction. Partial data beats no data."""
            try:
                return fn()
            except Exception as exc:
                log.debug("pe %s failed: %s", label, exc)
                problems.append(f"{label}: {type(exc).__name__}: {exc}")
                return default

        coff, optional = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        size = ctx["size"]

        data: dict[str, Any] = {
            "pe_type": "PE32+" if optional.Magic == MAGIC_PE32_PLUS else "PE32",
            "machine": coff.Machine,
            "machine_label": _lookup(_pefile.MACHINE_TYPE, coff.Machine),
            "subsystem": optional.Subsystem,
            "subsystem_label": _lookup(_pefile.SUBSYSTEM_TYPE, optional.Subsystem),
            "characteristics": coff.Characteristics,
            "is_dll": bool(coff.Characteristics & FILE_DLL),
            "is_system": bool(coff.Characteristics & FILE_SYSTEM),
            "is_driver": optional.Subsystem == SUBSYSTEM_NATIVE,
            "image_base": optional.ImageBase,
            "timestamp": coff.TimeDateStamp,
            "timestamp_iso": _iso_timestamp(coff.TimeDateStamp),
            "entry_point": optional.AddressOfEntryPoint,
        }

        data["sections"] = attempt("sections", lambda: self._sections(pe, ctx, config), [])
        starved = [s["name"] for s in data["sections"]
                   if s.get("entropy_skipped") == "budget_exhausted"]
        if starved:
            problems.append(
                "sections: the entropy budget ran out, so "
                f"{len(starved)} section(s) were not scored: {', '.join(starved[:8])}")
        data["entry_point_section"] = _section_for_rva(
            data["sections"], optional.AddressOfEntryPoint)

        # `imports_parsed` defaults to False here on purpose. If reading the
        # import table failed outright, the one thing that is certainly not
        # known is that the file has no imports.
        data.update(attempt("imports", lambda: self._imports(pe, config),
                            {"imports": {}, "import_count": 0, "imphash": None,
                             "imports_truncated": False, "imports_parsed": False,
                             "api_names": [], "api_capabilities": {}}))
        data.update(attempt("exports", lambda: self._exports(pe, config),
                            {"exports": [], "export_count": 0,
                             "exports_truncated": False}))
        data["tls_callbacks"] = attempt("tls", lambda: self._tls(pe, config), [])
        data["debug"] = attempt("debug", lambda: self._debug(pe, config), [])
        data["pdb_path"] = next((e["pdb_path"] for e in data["debug"] if e.get("pdb_path")),
                                None)
        data["certificate"] = attempt(
            "certificate", lambda: self._certificate(pe, size, config),
            {"present": False, "common_names": [], "validated": False})
        data["overlay"] = attempt(
            "overlay",
            lambda: self._overlay(pe, size, config, data["certificate"]), None)

        # pefile records a warning and carries on where it would otherwise
        # have to give up: an import directory at an impossible RVA, a
        # structure that overlaps another. Discarding those leaves the report
        # asserting an absence that was really a failure to look.
        warnings = attempt("warnings", pe.get_warnings, [])
        limit = config_int(config, "pe_max_listed_symbols", 256)
        if warnings:
            data["warnings"] = warnings[:limit]

        if problems:
            # Recorded inside the data rather than raised, so a file that
            # defeats one directory still yields the others. The pipeline's
            # `report.errors` is for an extractor that produced nothing, and
            # the CLI renders both, because either one means a report is
            # thinner than it looks.
            data["parse_errors"] = problems
        return data

    def _sections(self, pe, ctx: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """The section table, with entropy scored inside a shared budget.

        The per-region cap alone is not a bound. A section table is 40 bytes
        per entry and pefile will parse thousands of them, so a header under
        100 KB can ask for a cap's worth of histogram work several thousand
        times over. The budget is therefore spent across the whole table.

        How it is divided matters as much as that it exists. Spending it in
        table order lets a file starve a section by putting it last, and
        section order has no effect on loading, so that would be a free
        evasion: move the packed section to the end and it is never scored.
        `_share_budget` allocates by size instead, which no reordering
        changes.

        A section granted less than the entropy floor is not scored at all.
        Scoring 64 bytes of a 16 MB section produces a ratio above 1.0 - the
        reference model is out of range below about 128 bytes - and that is a
        `medium` finding bought with a forged size field.
        """
        cap = config_int(config, "pe_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        size = ctx["size"]

        lengths = []
        for section in pe.sections:
            start = section.PointerToRawData
            # A section table may claim raw data that runs past the end of the
            # file. Score what is actually there, not what it says is there.
            lengths.append(
                max(0, min(section.SizeOfRawData, size - start)) if start < size else 0)
        grants = _share_budget([min(length, cap) for length in lengths],
                               config_int(config, "pe_entropy_budget_bytes", 67108864))

        out = []
        for section, length, grant in zip(pe.sections, lengths, grants):
            name = safe_text(section.Name.rstrip(b"\x00"), 64)
            characteristics = section.Characteristics
            skipped = None
            if length < floor:
                skipped = "too_short" if length else "no_bytes"
            elif grant < floor:
                skipped = "budget_exhausted"
            if skipped:
                entropy, ratio, sampled, scored = None, None, False, 0
            else:
                entropy, ratio, sampled, scored = region_entropy(
                    pe.__data__, section.PointerToRawData, length, grant)
                if not scored:
                    skipped = "unreadable"
            out.append({
                "name": name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "raw_pointer": section.PointerToRawData,
                "scored_bytes": scored,
                "characteristics": characteristics,
                "readable": bool(characteristics & SCN_MEM_READ),
                "writable": bool(characteristics & SCN_MEM_WRITE),
                "executable": bool(characteristics & SCN_MEM_EXECUTE),
                "code": bool(characteristics & SCN_CNT_CODE),
                "uninitialised": bool(characteristics & SCN_CNT_UNINITIALIZED),
                "entropy": entropy,
                "entropy_ratio": ratio,
                "entropy_sampled": sampled,
                # Why there is no figure, when there is none. "the section was
                # empty", "the section pointed past the end of the file" and
                # "there was no budget left to read it" are three different
                # facts, and a null with no reason attached is the shape of a
                # report that looks clean because nobody looked.
                "entropy_skipped": skipped,
            })
        return out

    def _imports(self, pe, config: dict[str, Any]) -> dict[str, Any]:
        """The import table, and whether it was actually read.

        "No imports" and "an import table this parser could not follow" are
        different facts about a file, and only the first is evidence that the
        binary resolves its API at runtime. pefile signals the second by
        recording a warning and defining no `DIRECTORY_ENTRY_IMPORT`, which
        looks identical to the first unless the directory entry is consulted.
        A forged import RVA would otherwise earn a medium finding, and the
        gate exits non-zero on a medium.
        """
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        claimed = (len(directory) > DIRECTORY_IMPORT
                   and bool(directory[DIRECTORY_IMPORT].VirtualAddress))
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        limit = config_int(config, "pe_max_listed_symbols", 256)
        imports: dict[str, list[str]] = {}
        total, truncated = 0, False
        matched: set[str] = set()
        for entry in entries or []:
            dll = safe_text(entry.dll or b"", 256)
            names = []
            for imported in entry.imports:
                total += 1
                symbol = (safe_text(imported.name, 256) if imported.name
                          else f"#{imported.ordinal}")
                # Matched before the display cap is applied, for the reason
                # the strings extractor matches before its retained cap: a
                # binary with three thousand imports is exactly the one whose
                # interesting symbol sits past entry 256, and a capability
                # that depends on how long the list was allowed to get is not
                # a fact about the file.
                canonical, _categories = apis.match_symbol(symbol)
                if canonical is not None:
                    matched.add(canonical)
                if len(names) >= limit:
                    truncated = True
                    continue
                names.append(symbol)
            imports.setdefault(dll, []).extend(names)
        # imphash is computed over the import table pefile parsed, so it is
        # unaffected by the display cap above.
        imphash = pe.get_imphash() if imports else None
        return {
            "imports": imports,
            "import_count": total,
            "imphash": imphash or None,
            "imports_truncated": truncated,
            "imports_parsed": bool(entries) or not claimed,
            "api_names": sorted(apis.display(n) for n in matched),
            "api_capabilities": apis.categorise(matched, view="import"),
        }

    def _exports(self, pe, config: dict[str, Any]) -> dict[str, Any]:
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = getattr(directory, "symbols", []) if directory else []
        limit = config_int(config, "pe_max_listed_symbols", 256)
        names = [safe_text(s.name, 256) if s.name else f"#{s.ordinal}"
                 for s in symbols[:limit]]
        return {
            "exports": names,
            "export_count": len(symbols),
            "exports_truncated": len(symbols) > limit,
        }

    def _tls(self, pe, config: dict[str, Any]) -> list[int]:
        """Walk the TLS callback array.

        pefile parses the TLS directory but not the callback list it points
        at, and the list is worth having: a TLS callback runs before the entry
        point, which is exactly why it is used to defeat a debugger set to
        break there.

        Two bounds, both because the file supplies the numbers. The walk is
        capped, since the array ends at a terminator a hostile file can
        decline to provide. And the address must resolve into a real section
        before it is followed.

        That second test is stronger than it first looks like it needs to be,
        because `pefile.get_data` resolves an address three ways and only one
        of them is the array. A negative RVA, from `AddressOfCallBacks` below
        `ImageBase`, slices backwards from the header buffer and returns DOS
        stub and section-table bytes. An RVA inside the declared image but
        covered by no section falls through to being treated as a raw file
        offset, which on a file with an overlay returns the overlay. Both
        produce plausible-looking addresses, and each one earns a finding on
        the way out: invented structure filed as extracted data. Checking the
        RVA against `SizeOfImage` does not catch either, because `SizeOfImage`
        is also a field in the file. Landing in a section does.
        """
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if not directory or not getattr(directory, "struct", None):
            return []
        address = getattr(directory.struct, "AddressOfCallBacks", 0)
        optional = pe.OPTIONAL_HEADER
        rva = address - optional.ImageBase
        if not address or not _in_a_section(pe, rva):
            return []

        width = 8 if optional.Magic == MAGIC_PE32_PLUS else 4
        callbacks: list[int] = []
        for _ in range(config_int(config, "pe_max_tls_callbacks", 64)):
            if not _in_a_section(pe, rva):
                break
            raw = _safe_data(pe, rva, width)
            if len(raw) < width:
                break
            value = int.from_bytes(raw, "little")
            if not value:
                break
            callbacks.append(value)
            rva += width
        return callbacks

    def _debug(self, pe, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Walk the debug directory without letting pefile size the read.

        pefile parses a CodeView record by slicing `SizeOfData` bytes out of
        the mapping and packing whatever is left over into `PdbFileName`.
        `SizeOfData` is a field in the file, so a one-DWORD edit turns a PDB
        path into a copy of the whole sample: a 40 MB file produced a 40 MB
        string, a 200 MB peak and an 84 MB JSON report, with no error raised.
        That is the bounded-memory invariant lost to a single forged number,
        so the directory is walked here and every read is given a length.
        """
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directory) <= DIRECTORY_DEBUG:
            return []
        rva, size = directory[DIRECTORY_DEBUG].VirtualAddress, directory[DIRECTORY_DEBUG].Size
        if not rva or not size:
            return []

        limit = config_int(config, "pe_max_pdb_bytes", 1024)
        out = []
        for index in range(min(size // DEBUG_ENTRY_SIZE,
                               config_int(config, "pe_max_debug_entries", 32))):
            raw = _safe_data(pe, rva + index * DEBUG_ENTRY_SIZE, DEBUG_ENTRY_SIZE)
            if len(raw) < DEBUG_ENTRY_SIZE:
                break
            _, stamp, _, _, kind, data_size, data_rva, data_pointer = struct.unpack(
                "<IIHHIIII", raw)
            out.append({
                "type": kind,
                "type_label": _lookup(_pefile.DEBUG_TYPE, kind),
                "timestamp": stamp,
                "pdb_path": (self._pdb_path(pe, data_rva, data_pointer, data_size, limit)
                             if kind == DEBUG_TYPE_CODEVIEW else None),
            })
        return out

    @staticmethod
    def _pdb_path(pe, rva: int, pointer: int, size: int, limit: int) -> str | None:
        """Read the CodeView record by RVA, or by file pointer if that fails.

        The entry carries both, and a debug record is not required to be
        mapped: some linkers leave `AddressOfRawData` zero and only the file
        pointer valid. Reading the RVA alone also hands an attacker a
        one-DWORD eraser for the build path, which is one of the few
        attributable strings a stripped binary has.
        """
        if not size:
            return None
        take = min(size, limit)
        for record in (_safe_data(pe, rva, take), _file_data(pe, pointer, take)):
            offset = CODEVIEW_PATH_OFFSET.get(record[:4])
            if offset is None:
                continue
            path = safe_text(record[offset:].split(b"\x00")[0], 1024)
            if path:
                return path
        return None

    def _certificate(self, pe, size: int, config: dict[str, Any]) -> dict[str, Any] | None:
        """Presence and embedded names. Never validity: see
        `certificate_common_names` for why that line is drawn here."""
        absent = {"present": False, "common_names": [], "validated": False}
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= DIRECTORY_SECURITY:
            return absent
        entry = directories[DIRECTORY_SECURITY]
        # This one entry holds a file offset, not an RVA.
        offset, length = entry.VirtualAddress, entry.Size
        if not offset or not length or offset >= size:
            return absent
        scanned = min(length, size - offset,
                      config_int(config, "pe_max_certificate_bytes", 1048576))
        blob = bytes(pe.__data__[offset: offset + scanned])
        return {
            "present": True,
            "offset": offset,
            "size": entry.Size,
            "scanned_bytes": len(blob),
            # A name past the ceiling is a name this scan did not look for,
            # and a report that says so is the difference between "no other
            # signer" and "no other signer that I read far enough to see".
            "scan_truncated": len(blob) < entry.Size,
            "common_names": certificate_common_names(blob),
            "validated": False,
        }

    def _overlay(self, pe, size: int, config: dict[str, Any],
                 certificate: dict[str, Any] | None) -> dict[str, Any] | None:
        """Bytes past the last section that no loader maps.

        The certificate table lives out here too, because that is where the
        format puts it, and counting it as an overlay would report every
        signed binary as carrying an appended payload. It is subtracted when
        it sits at the tail, which is the only place it is allowed to sit,
        *and* begins at or after the overlay does. Without that second test a
        forged security directory covering most of the file erases the
        overlay from the report entirely, which hides a dropper's payload for
        the price of two DWORDs.
        """
        start = pe.get_overlay_data_start_offset()
        if start is None:
            return None
        end = size
        if certificate and certificate.get("present"):
            offset = certificate["offset"]
            tail = offset + certificate["size"]
            if offset >= start and tail >= size - 8:  # alignment padding is permitted
                end = offset
        if start >= end:
            return None
        length = end - start
        cap = config_int(config, "pe_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        entropy, ratio, sampled, _ = (region_entropy(pe.__data__, start, length, cap)
                                      if length >= floor else (None, None, False, 0))
        return {
            "offset": start,
            "size": length,
            "fraction_of_file": round(length / size, 4) if size else 0.0,
            "excludes_certificate": end != size,
            "entropy": entropy,
            "entropy_ratio": ratio,
            "entropy_sampled": sampled,
        }

    # findings

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn PE structure into things worth a human's attention.

        Nothing here is `high`. `extension_mismatch` earns high because PE
        content under a `.pdf` extension is near-unambiguous deception;
        packing is not deception, it is the normal state of most installers.
        And `GATE_SEVERITY` is medium, so every medium below is a new reason
        for this tool to exit non-zero in somebody's CI. A finding sits at
        medium only if a file deserves a human because of it alone.
        """
        out: list[dict[str, Any]] = []
        sections = data.get("sections") or []
        out.extend(self._section_findings(sections, data, config))
        out.extend(self._import_findings(data, config))
        out.extend(self._other_findings(data, config))
        return out

    def _section_findings(self, sections, data, config):
        out = []
        threshold = config_ratio(config, "pe_section_entropy_ratio", 0.94)
        percent = config_int(config, "pe_virtual_size_percent", 200, minimum=100)
        packers = {p.lower() for p in config_list(config, "pe_packer_sections", [])}
        standard = {s.lower() for s in config_list(config, "pe_standard_sections", [])}

        hot = [s for s in sections
               if s.get("entropy_ratio") is not None and s["entropy_ratio"] >= threshold]
        if hot:
            out.append(mk_finding(self.name, "section_entropy_high",
                "high-entropy section(s): " + ", ".join(
                    f"{s['name']} at {s['entropy_ratio']} of random" for s in hot) +
                ", consistent with a packed, compressed or encrypted section",
                "medium",
                evidence=[{"name": f"{s['name']}.entropy_ratio",
                           "value": s["entropy_ratio"]} for s in hot],
                discriminator=", ".join(s["name"] for s in hot)))

        wx = [s["name"] for s in sections if s["writable"] and s["executable"]]
        if wx:
            out.append(mk_finding(self.name, "writable_executable_section",
                f"section(s) {', '.join(wx)} are both writable and executable, "
                "which is what code that rewrites itself needs and what a "
                "compiler does not emit", "medium"))

        # A virtual size far above the raw size is space reserved in memory
        # that no bytes in the file fill: the room an unpacker unpacks into.
        swollen = [s for s in sections
                   if not s["uninitialised"] and s["raw_size"]
                   and s["virtual_size"] * 100 > s["raw_size"] * percent]
        if swollen:
            out.append(mk_finding(self.name, "virtual_size_mismatch",
                "section(s) " + ", ".join(
                    f"{s['name']} ({s['virtual_size']} virtual vs {s['raw_size']} raw)"
                    for s in swollen) +
                " reserve far more memory than the file provides, the shape of "
                "an unpacking stub", "medium"))

        named = [s["name"] for s in sections if s["name"].lower() in packers]
        if named:
            out.append(mk_finding(self.name, "known_packer_section",
                f"section name(s) {', '.join(named)} match a known packer's "
                "conventional layout", "medium"))

        entry = data.get("entry_point_section")
        entry_section = next((s for s in sections if s["name"] == entry), None)
        if entry_section and entry_section["writable"]:
            out.append(mk_finding(self.name, "entry_point_in_writable_section",
                f"the entry point at {hex(data.get('entry_point', 0))} is in "
                f"'{entry}', which is writable, so the first code to run can "
                "be modified before it runs", "medium"))

        odd = [s["name"] for s in sections
               if s["name"].lower() not in standard and s["name"].lower() not in packers]
        if odd:
            out.append(mk_finding(self.name, "nonstandard_section_name",
                f"section name(s) {', '.join(odd)} are not names a mainstream "
                "toolchain emits", "low"))
        return out

    def _import_findings(self, data, config):
        out = []
        count = data.get("import_count", 0)
        few = config_int(config, "pe_few_imports", 6)
        # A DLL that imports nothing is unusual; an executable that imports
        # nothing cannot call the operating system it runs on, so it must
        # resolve its own imports at runtime, which is what a packed stub does.
        #
        # Gated on `imports_parsed` because an import table that could not be
        # followed is not an absent one, and this is the finding a forged
        # import RVA would otherwise buy at medium.
        # A module with no entry point and no executable section carries no
        # code, and the finding below is an argument about code: a binary with
        # no imports must resolve them at runtime, which takes instructions to
        # do. There are none here, so the premise does not hold.
        #
        # This is not a special case invented for Windows. It is the standard
        # Windows localisation mechanism - every `en-US\*.mui` is a
        # resource-only module, and so are a large share of the DLLs beside
        # them. Measured over a sample of System32, `no_imports` fired on 17.9%
        # of ordinary files at medium and was the sole cause of flagging on 48
        # of the 94 files the gate caught. It was the single largest
        # contributor to a 32.3% false positive rate, against 0.6% on Linux.
        #
        # Reported at `info` rather than passed over in silence: a PE with no
        # code is a fact an analyst wants, and without it the absence of every
        # import-derived finding has no visible explanation.
        sections = data.get("sections") or []
        resource_only = bool(sections) and not data.get("entry_point") and not any(
            s["code"] or s["executable"] for s in sections)
        if resource_only:
            out.append(mk_finding(self.name, "resource_only_module",
                "no entry point and no executable section, so this module "
                "carries resources rather than code", "info"))

        if (not count and data.get("imports_parsed")
                and not data.get("is_driver") and not resource_only):
            out.append(mk_finding(self.name, "no_imports",
                "no imports at all, so this cannot reach the API it needs "
                "without resolving it at runtime, the usual mark of a packed "
                "or self-loading binary", "medium"))
        elif 0 < count < few:
            names = sorted({d for d in (data.get("imports") or {})})
            out.append(mk_finding(self.name, "few_imports",
                f"only {count} imported symbol(s) from {', '.join(names)}, thin "
                "enough to suggest the real import table is resolved at "
                "runtime", "low"))

        # The capabilities the import table names outright. This is the
        # stronger of the two views: an import is a symbol the loader will
        # resolve, so there is no question of whether the name means what it
        # looks like. It still does not reach medium, because every name here
        # is one that legitimate software also calls.
        out.extend(apis.capability_findings(
            self.name, data.get("api_capabilities") or {},
            config_int(config, "api_min_names_per_capability", 2),
            view="import"))
        return out

    def _other_findings(self, data, config):
        out = []
        timestamp = data.get("timestamp")
        floor = config_int(config, "pe_min_timestamp", 725846400)
        if timestamp is not None and (timestamp == 0 or timestamp < floor
                                      or timestamp > _now() + 86400):
            out.append(mk_finding(self.name, "implausible_timestamp",
                f"compile timestamp {timestamp} ({data.get('timestamp_iso')}) is "
                "zero, older than the format, or in the future, so it has been "
                "stripped or forged", "low"))

        overlay = data.get("overlay")
        if overlay:
            large = config_int(config, "pe_large_overlay_bytes", 1048576)
            if overlay["size"] >= large:
                out.append(mk_finding(self.name, "large_overlay",
                    f"{overlay['size']} bytes appended after the last section "
                    f"({overlay['fraction_of_file']} of the file), which no "
                    "loader maps and which is where a dropper keeps its payload",
                    "low"))
            else:
                out.append(mk_finding(self.name, "overlay_present",
                    f"{overlay['size']} bytes appended after the last section",
                    "info"))

        callbacks = data.get("tls_callbacks") or []
        if callbacks:
            out.append(mk_finding(self.name, "tls_callbacks_present",
                f"{len(callbacks)} TLS callback(s), which run before the entry "
                "point and therefore before a debugger breaking on it", "low"))

        certificate = data.get("certificate")
        if certificate and certificate.get("present"):
            names = certificate.get("common_names") or []
            detail = "an embedded certificate table is present"
            if names:
                detail += f", naming {', '.join(names[:3])}"
            out.append(mk_finding(self.name, "signature_present",
                detail + "; nothing here validates it", "info"))
        return out


def _in_a_section(pe, rva: int) -> bool:
    """Whether an RVA lands in a section that has bytes behind it.

    `pefile.get_data` will resolve an address that is not in any section, by
    falling back to the header buffer or to treating it as a file offset. That
    is helpful when parsing a structure whose location is already trusted and
    dangerous when following a pointer the file supplied.
    """
    if rva < 0:
        return False
    try:
        section = pe.get_section_by_rva(rva)
    except Exception:
        return False
    return section is not None and bool(section.SizeOfRawData)


def _file_data(pe, offset: int, length: int) -> bytes:
    """A bounded read at a file offset rather than an RVA."""
    if offset <= 0 or length <= 0 or offset >= len(pe.__data__):
        return b""
    return bytes(pe.__data__[offset: offset + length])


def _safe_data(pe, rva: int, length: int) -> bytes:
    """A bounded read at an RVA that may not be a real one.

    `pefile.get_data` raises on an address it cannot resolve, which is the
    right behaviour for a caller parsing one structure and the wrong one for a
    caller walking an array: a single bad entry should end the walk, not
    discard the entries already read.
    """
    if rva < 0 or length <= 0:
        return b""
    try:
        return pe.get_data(rva, length) or b""
    except Exception:
        return b""


def _now() -> int:
    return int(time.time())


def _iso_timestamp(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _section_for_rva(sections: list[dict[str, Any]], rva: int) -> str | None:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"], 1)
        if start <= rva < start + span:
            return section["name"]
    return None
