# -* coding: utf-8 *-
# @auhtor: AbhiTheModder

from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()


# ---------------- ssl_verify_peer_cert ----------------
# Android patterns adapted from AbhiTheModder/termux-scripts/flutter_ssl_patch.py
patterns = {
        "arm64": [
            ("F. 0F 1C F8 F. 5. 01 A9 F. 5. 02 A9 F. .. 03 A9 .. .. .. .. 68 1A 40 F9", 0),
            ("F. 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9", 0),
            ("FF 43 01 D1 FE 67 01 A9 .. .. 06 94 .. 7. 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9", 0),
            ("F. 0F 1C F8 F. .. 0. .. .. .. .. .9 .. .. 0. .. 68 1A 40 F9 15 .. 4. F9 B5 00 00 B4 B6 46 40 F9", 0),
            ("FE 0F 1C F8 ?? ?? ?? 9? 13 00 40 F9 F4 03 00 AA 68 1A 40 F9 15 E9 40 F9 ?? ?? ?? B4 96 02 44 F9", 0),
            ("FF .3 01 D1 F. .. 01 A9 .. .. .. 94 .. .. .. 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9", 1),
            ("FF C3 01 D1 FD 7B 01 A9 ?? ?? ?? 9? 08 C0 46 39 ?? ?? ?? 34 F4 03 1F 2A E0 03 14 2A ?? ?? ?? 9? FD 7B 41 A9", 1),
        ],
        "arm": [
            ("2D E9 F. 4. D0 F8 00 80 81 46 D8 F8 18 00 D0 F8", 0),
        ],
        "x64": [
            ("55 41 57 41 56 41 55 41 54 53 50 49 89 fe 48 8b 1f 48 8b 43 30 4c 8b b8 d0 01 00 00 4d 85 ff 74 12 4d 8b a7 90 00 00 00 4d 85 e4 74 4a 49 8b 04 24 eb 46", 0),
            ("55 41 57 41 56 41 55 41 54 53 50 49 89 f. 4. 8b .. 4. 8b 4. 30 4c 8b .. .. 0. 00 00 4d 85 .. 74 1. 4d 8b", 0),
            ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74", 0),
            ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB", 0),
            ("55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02 50 48 8B AF A. 00 00 00 48 85 ED 74 7. 48 83 7D 00 00 74", 1),
        ],
        "x86": [
            ("55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01", 0),
        ],
    }


# ---------------- Get r2 Version ----------------
def get_r2_version():

    try:
        result = M.subprocess.run(["r2", "-V"], capture_output=True, text=True, check=True)
        results = result.stdout.strip().split()

        for result in results:
            if result.startswith(("5.", "6.")):
                result = result.split("-")[0]
                return result

        return None

    except (M.subprocess.CalledProcessError, FileNotFoundError):
        return None


# ---------------- Find Offset ----------------
def find_offset(r2, patterns, is_iA=False):

    if is_iA:
        arch = M.json.loads(r2.cmd("iAj"))
    else:
        arch = M.json.loads(r2.cmd("iaj"))

    arch_value = arch["bins"][0]["arch"]
    arch_bits = arch["bins"][0]["bits"]

    if arch_value == "arm" and arch_bits == 64:
        arch = "arm64"
    elif arch_value == "arm" and arch_bits in (16, 32):
        arch = "arm"
    elif arch_value == "x86" and arch_bits == 64:
        arch = "x64"
    elif arch_value == "x86" and arch_bits == 32:
        arch = "x86"
    else:
        print(f"\n{C.ERROR} Unsupported architecture: {arch_value}\n")
        return

    matches = []
    seen = set()
    for pattern, retval in patterns.get(arch, []):
        # radare2 uses dots for wildcard nibbles.
        search_result = r2.cmd(f"/x {pattern.replace('?', '.')}")
        for line in search_result.splitlines():
            fields = line.split()
            if not fields or not M.re.fullmatch(r"0x[0-9a-fA-F]+", fields[0]):
                continue
            offset = fields[0]
            if offset in seen:
                continue
            seen.add(offset)
            matches.append((offset, f"wao ret{retval}"))
            print(f"\n{C.X}{C.C} Matched function at: {C.PN}{offset}\n")
    return matches


# ---------------- Patch Flutter SSL ----------------
def Patch_Flutter_SSL(decompile_dir, isAPKEditor):

    print(f"\r{C.X}{C.C} Flutter SSL Patch, Script by {C.OG}🇮🇳 AbhiTheM0dder 🇮🇳\n")

    try:
        r2_version = tuple(map(int, get_r2_version().split(".")))
        ia_version = tuple(map(int, "5.9.5".split(".")))

        if r2_version <= ia_version:
            is_iA = True
        else:
            is_iA = False

    except Exception as e:
        exit(f"\n{C.ERROR} {str(e)}\n")

    architectures = ["arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86"]
    lib_so_path = None

    for arch in architectures:
        lib = "root/lib" if isAPKEditor else "lib"
        potential_path = M.os.path.join(decompile_dir, lib, arch, 'libflutter.so')

        if M.os.path.exists(potential_path):
            lib_so_path = potential_path
            break

    if lib_so_path:
        print(f"\n{C.S} Found {C.E} {C.OG}➸❥ {C.Y}{arch}/{M.os.path.basename(lib_so_path)} {C.G} ✔\n")

        # ---------------- Detect Flutter Dart Version ----------------
        with open(lib_so_path, "rb") as so_file:

            read = so_file.read().decode(
                "ascii",
                errors="ignore"
            ).replace("\x00", "")

            if " (stable)" in read:
                version_code = (
                    M.re.findall(
                        r"\d+\.\d+\.\d+",
                        read[:read.find(" (stable)")]
                    ) or ["Unknown"]
                )[-1]
            else:
                version_code = "Unknown"

            print(f"\n{C.S} Flutter Dart Version {C.E} {C.OG}➸❥  {C.PN}{version_code}  {C.G}✔\n")

    else:
        exit(f"\n{C.ERROR} libflutter.so not found in any of the specified architectures {architectures}\n")

        M.shutil.rmtree(decompile_dir)

    import r2pipe

    if r2pipe.in_r2():
        r2 = r2pipe.open()
        r2.cmd("e log.quiet=true")
        r2.cmd("oo+")
    else:
        r2 = r2pipe.open(lib_so_path, flags=["-w", "-e", "log.quiet=true"])

    print(f"\n{C.X}{C.G} Analyzing function calls...\n")

    r2.cmd("aac")

    print(f"\n{C.X}{C.G} Searching for offset...\n")

    result = find_offset(r2, patterns, is_iA)

    if result:
        for offset, patch_cmd in result:
            r2.cmd(f"{offset}")
            r2.cmd(patch_cmd)

        print(f"\n{C.X}{C.C} ssl_verify_peer_cert: {C.G}Patched Successfully  ✔\n")

    else:
        print(f"\n{C.ERROR} ssl_verify_peer_cert Not Found.  ✘\n")

    print(f"{C.CC}{'_' * 61}\n\n")

    r2.quit()
