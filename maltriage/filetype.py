"""
Format identification from magic bytes.

Dependency-free on purpose, and the first extractor the pipeline runs: what it
publishes into `ctx` is what every later phase gates on.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any

from . import attack
from .base import HeaderExtractor
from .config import config_list
from .models import mk_finding
from .pe import certificate_range


# file type

class FileTypeExtractor(HeaderExtractor):
    """Identify the format from magic bytes.

    Deliberately dependency-free. `python-magic` needs libmagic installed,
    which is friction for anyone cloning the repo, and a small signature table
    covers the formats that matter for triage.

    Costs no I/O of its own. Publishes `family` to the context, which is what
    lets the format-specific parsers arriving in v0.2 gate themselves.
    """

    name = "filetype"

    def read_header(self, header: bytes, path: Path, ctx: dict[str, Any],
                    config: dict[str, Any]) -> dict[str, Any]:
        label, family = "unknown", "unknown"
        for signature in config_list(config, "signatures", []):
            # A malformed entry is skipped rather than aborting the extractor,
            # so one bad signature cannot cost every later one. validate_config
            # reports it separately.
            if not isinstance(signature, (list, tuple)) or len(signature) != 4:
                continue
            offset, magic_hex, lbl, fam = signature
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                continue
            try:
                magic = bytes.fromhex(str(magic_hex))
            except ValueError:
                continue
            if magic and header[offset : offset + len(magic)] == magic:
                label, family = lbl, fam
                break

        ctx["family"] = family
        # Published here because phase 1 is the only phase that runs before
        # the entropy stream, and because this range is knowable from the
        # header alone -- the security directory holds a file offset, not an
        # RVA. `ctx` is the channel the pipeline already documents for this:
        # "each sees what the previous one published".
        # `ctx.get`, not `ctx[...]`: a caller may hand this extractor a bare
        # context, and identifying the format is this extractor's job -- losing
        # it because an optional key for somebody else's optimisation was
        # absent would be a poor trade. Without a size there is no range, and
        # the entropy pass then scores every byte, which is the safe direction.
        size = ctx.get("size")
        if family == "pe" and size:
            found = certificate_range(header, size)
            if found:
                ctx["certificate_range"] = found
        return {
            "magic_label": label,
            "family": family,
            "extension": path.suffix.lower(),
            "header_hex": header[:16].hex(),
        }

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        if data["family"] == "unknown":
            detail = (f"no signature match, first bytes {data['header_hex']}"
                      if data["header_hex"] else "file is empty, nothing to identify")
            out.append(mk_finding(self.name, "unrecognised_format", detail, "info"))
        executable = data["family"] in config_list(config, "executable_families", [])
        masquerading = data["extension"] in config_list(config, "document_extensions", [])
        if executable and masquerading:
            out.append(mk_finding(self.name, "extension_mismatch",
                f"content is {data['magic_label']} but the extension is "
                f"'{data['extension']}', masquerading as a document", "high",
                evidence=[{"name": "family", "value": data["family"]},
                          {"name": "extension", "value": data["extension"]},
                          {"name": "magic_offset", "value": data.get("magic_offset", 0)}],
                discriminator=data["family"],
                # The only finding maltriage maps on its own account, and it
                # qualifies for the same reason it is this project's only
                # `high`: there is no benign reason for a PE to be called
                # `invoice.pdf`. `attack.py` records the findings that were
                # considered and refused.
                mitre=[attack.MASQUERADE_FILE_TYPE]))
        return out
