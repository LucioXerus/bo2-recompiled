#!/usr/bin/env python3
"""Post-codegen patches for the recompiled Black Ops II sources.

Codegen regenerates `generated/*.cpp` from scratch, so fixes that have to live in
recompiled code are applied here and re-applied on every codegen run.
"""

import glob
import os
import sys


def patch_local_user_count(root: str) -> bool:
    """Zero the local-user count output before sub_82695280 enumerates users.

    `sub_82538C80` calls `sub_82695280(r3 = &count)` which forwards to the
    registered enumeration callback. If that callback is a no-op or an
    end-of-table sentinel it never writes `count`, and the caller then treats
    whatever happens to be on the stack there as a live count. On BO2 MP that
    value routinely lands in the millions, so the copy loop below walks off the
    stack and the game dies reading 0x70170000 right after local sign-in.

    Zero-initialising the slot first makes a silent callback return 0 instead of
    uninitialised stack, which is what the caller already handles correctly.
    """
    marker = "// stw r10,7520(r11)\n"
    anchor = (
        "// stw r10,3928(r1)\n"
        "\tREX_STORE_U32(ctx.r1.u32 + 3928, ctx.r10.u32);\n"
    )
    fix = "\tREX_STORE_U32(ctx.r1.u32 + 80, 0);  // [patched] no default user count\n"

    patched_any = False
    for path in glob.glob(os.path.join(root, "generated", "default_mp_recomp.*.cpp")):
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()

        start = text.find("DEFINE_REX_FUNC(sub_82538C80) {")
        if start < 0:
            continue

        end = text.find("\nDEFINE_REX_FUNC(", start + 1)
        if end < 0:
            end = len(text)

        body = text[start:end]
        if fix in body:
            patched_any = True
            continue

        pos = body.find(anchor)
        if pos < 0:
            print(f"[patch] {path}: sub_82538C80 shape changed, anchor not found", file=sys.stderr)
            return False

        pos += len(anchor)
        body = body[:pos] + fix + body[pos:]
        text = text[:start] + body + text[end:]

        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

        print(f"[patch] {os.path.basename(path)}: zeroed local-user count in sub_82538C80")
        patched_any = True

    if not patched_any:
        print("[patch] sub_82538C80 not found; nothing to patch", file=sys.stderr)
    return patched_any


def main() -> int:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "default_mp"))
    if not os.path.isdir(os.path.join(root, "generated")):
        print(f"[patch] no generated sources under {root}", file=sys.stderr)
        return 1

    ok = patch_local_user_count(root)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
