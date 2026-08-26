/*
    maltriage bundled rules: structure, not signatures.
    See AUTHORING.md in this directory before adding a rule.

    Every rule here describes the *shape* of a file: a header where one does
    not belong, an encoded executable inside a document, a container feature
    that exists to make something run. None of them name a malware family,
    because a signature list rots and this repository has no corpus to keep
    one honest.

    Nothing here duplicates a finding the PE extractor already produces.
    Packed section names, writable executable sections and overlays are
    v0.2's job and are not restated as rules.

    Severity is declared per rule in `meta` and defaults to `info` when it is
    absent. `GATE_SEVERITY` is medium, so every medium below is a reason for
    this tool to exit non-zero in somebody's CI.
*/

rule embedded_pe_header : structural executable
{
    meta:
        severity = "medium"
        description = "a Windows executable header appears inside a file that is not one"
        rationale = "a dropper carries its payload somewhere, and a document or archive with a PE header inside it is carrying something it has no reason to carry"
        false_negative = "a payload with the DOS stub stripped will not match; the stub is required here because two of these three strings alone match random data often enough to matter"

    strings:
        $mz   = { 4D 5A }
        $pe   = { 50 45 00 00 }
        $stub = "This program cannot be run in DOS mode"

    condition:
        uint16(0) != 0x5A4D and all of them
}

rule base64_encoded_pe_header : structural encoded
{
    meta:
        severity = "medium"
        description = "a base64-encoded Windows executable header"
        rationale = "an executable encoded as text is an executable somebody wanted to move through something that only carries text: a script, a config file, a document, an HTTP body"

    strings:
        // The encoding of 4D 5A 90 00, at each of the three byte alignments
        // base64 can place it at.
        $a = "TVqQAA" ascii wide
        $b = "1aQAAM" ascii wide
        $c = "NWkAAD" ascii wide
        // and the two other DOS header variants seen in the wild
        $d = "TVpQAA" ascii wide
        $e = "TVoAAA" ascii wide

    condition:
        any of them
}

rule hex_encoded_pe_header : structural encoded
{
    meta:
        severity = "low"
        description = "a hex-encoded Windows executable header"
        rationale = "same intent as base64, and low rather than medium because a hex dump of a legitimate binary in documentation looks identical"

    strings:
        $a = "4d5a9000" nocase ascii wide
        $b = "4d5a5000" nocase ascii wide
        $c = "\\x4d\\x5a\\x90" nocase ascii wide
        $d = "0x4d,0x5a,0x90" nocase ascii wide

    condition:
        any of them
}

rule embedded_elf_header : structural executable
{
    meta:
        severity = "low"
        description = "an ELF header appears inside a file that is not one"
        rationale = "the Linux counterpart of embedded_pe_header, at low because ELF has no equivalent of the DOS stub to raise confidence with"
        false_positive = "the four magic bytes alone occur once every 4 GB of random data, which is often enough to dirty a report on a packed or encrypted sample; EI_CLASS, EI_DATA and EI_VERSION are constrained here to take that to once every 4000 TB"

    strings:
        // magic, then EI_CLASS (32/64-bit), EI_DATA (LE/BE), EI_VERSION (1)
        $elf = { 7F 45 4C 46 (01 | 02) (01 | 02) 01 }

    condition:
        uint32(0) != 0x464C457F and $elf
}

rule pdf_with_automatic_action : structural document
{
    meta:
        severity = "low"
        description = "a PDF that runs something when it is opened"
        rationale = "an automatic action plus embedded script is how a PDF does anything at all without being asked; common in legitimate forms, which is why this is low"

    strings:
        $open = "/OpenAction" nocase
        $auto = "/AA" nocase
        $js   = "/JavaScript" nocase
        $js2  = "/JS" nocase

    condition:
        uint32be(0) == 0x25504446 and ($open or $auto) and ($js or $js2)
}

rule pdf_with_embedded_file : structural document
{
    meta:
        severity = "low"
        description = "a PDF carrying an embedded file"
        rationale = "a PDF is a container as well as a document, and the attachment is the part worth extracting in v0.5"

    strings:
        $spec = "/EmbeddedFile" nocase
        $file = "/Filespec" nocase

    condition:
        uint32be(0) == 0x25504446 and any of them
}

rule rtf_with_embedded_object : structural document
{
    meta:
        severity = "low"
        description = "an RTF carrying an embedded OLE object"
        rationale = "RTF has no macros, so an object is the mechanism it has; the object itself is v0.6's business"

    strings:
        $obj  = "\\objdata" nocase
        $ole  = "\\objemb" nocase
        $link = "\\objautlink" nocase

    condition:
        uint32be(0) == 0x7B5C7274 and any of them
}

rule ole_document_with_vba_project : structural document
{
    meta:
        severity = "low"
        description = "an OLE2 document containing a VBA project"
        rationale = "a marker, not an extraction: it says this file is worth what v0.6 will do to it, and macros in an Office document are ordinary enough that anything above low would gate on nothing"

    strings:
        $vba  = "_VBA_PROJECT" ascii wide nocase
        $dir  = "VBA" ascii wide

    condition:
        uint32be(0) == 0xD0CF11E0 and $vba and $dir
}
