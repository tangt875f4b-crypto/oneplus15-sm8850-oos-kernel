#!/usr/bin/env python3
import argparse
import io
import json
import os
import re
import struct
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KMIS = (
    "android12-5.10",
    "android13-5.10",
    "android13-5.15",
    "android14-5.15",
    "android14-6.1",
    "android15-6.6",
    "android16-6.12",
    "android17-6.18",
)
MODULE_ID = "susfs_guard_lkm"
MODULE_NAME = "SusFS LKM by uran"
MODULE_AUTHOR = "uran"
ARTIFACT_PREFIX = "SusFS-LKM-by-uran"
MODULE_SCRIPTS = (
    "customize.sh",
    "early-dispatch.sh",
    "kmi.sh",
    "late-load.sh",
    "load.sh",
    "post-fs-data.sh",
    "uninstall.sh",
)


def inspect_elf(data):
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a little-endian ELF64 image")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[2] != 183:
        raise ValueError("Expected AArch64")
    offset, size, count, names_index = header[6], header[11], header[12], header[13]
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size)
        for i in range(count)
    ]
    names_section = sections[names_index]
    names = data[names_section[4] : names_section[4] + names_section[5]]

    def string(table, index):
        return table[index : table.find(b"\0", index)].decode("utf-8", "replace")

    named = {string(names, section[0]): section for section in sections}
    symbols = []
    for section in sections:
        if section[1] != 2:
            continue
        linked = sections[section[6]]
        strings = data[linked[4] : linked[4] + linked[5]]
        for i in range(section[5] // section[9]):
            entry = struct.unpack_from("<IBBHQQ", data, section[4] + i * section[9])
            name = string(strings, entry[0])
            if name:
                symbols.append(name)
    modinfo = []
    if ".modinfo" in named:
        section = named[".modinfo"]
        modinfo = [
            s.decode("utf-8", "replace")
            for s in data[section[4] : section[4] + section[5]].split(b"\0")
            if s
        ]
    return {
        "elf_type": header[1],
        "modinfo": modinfo,
        "kcfi_symbols": sum(name.startswith("__kcfi_typeid_") for name in symbols),
        "module_symbols": symbols,
    }


def check_ko(kernel_bytes, kmi, expected_version=None):
    module = inspect_elf(kernel_bytes)
    series = kmi.split("-", 1)[1]
    if module["elf_type"] != 1 or not any(
        v.startswith(f"vermagic={series}.") for v in module["modinfo"]
    ):
        raise ValueError(f"Kernel module does not match AArch64 kernel {series} ET_REL")
    if not module["kcfi_symbols"] and not any(
        name.startswith("__cfi_") for name in module["module_symbols"]
    ):
        raise ValueError("Kernel module has neither legacy CFI nor kCFI symbols")
    for parameter in ("expose_proc", "su_ctx", "avc_su_ctx"):
        if not any(v.startswith(f"parmtype={parameter}:") for v in module["modinfo"]):
            raise ValueError(f"Kernel module missing expected parameter: {parameter}")
    if not any(
        n == "sus_path_sb_release" or n.startswith("sus_path_sb_release.")
        for n in module["module_symbols"]
    ):
        raise ValueError(f"Filesystem cleanup hook missing in {kmi}")
    if f"author={MODULE_AUTHOR}" not in module["modinfo"]:
        raise ValueError(f"Missing author={MODULE_AUTHOR} in .modinfo")
    if expected_version:
        if f"version={expected_version}" not in module["modinfo"]:
            raise ValueError(
                f"Expected version={expected_version} in .modinfo, got {module['modinfo']}"
            )
        expected_desc = f"description={MODULE_NAME} ({expected_version})"
        if expected_desc not in module["modinfo"]:
            raise ValueError(f"Missing {expected_desc!r} in .modinfo")
    return module


def check_loader(loader_bytes):
    loading = inspect_elf(loader_bytes)
    if loading["elf_type"] not in (2, 3):
        raise ValueError("Loader binary is not an AArch64 executable")


def resolve_version(publish_release=False, release_tag="", run_number=0):
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    raw_base = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    base_match = re.fullmatch(r"(v[0-9]+\.[0-9]+\.[0-9]+)(?:-r[0-9]+)?", raw_base)
    if not base_match:
        raise ValueError(f"Invalid VERSION contents: {raw_base!r}")
    base = base_match.group(1)

    short = commit[:7]
    tags_raw = subprocess.check_output(
        ["git", "tag", "-l", f"{base}-r*"], cwd=ROOT, text=True
    )
    revisions = []
    rev_re = re.compile(rf"^{re.escape(base)}-r([0-9]+)")
    for line in tags_raw.splitlines():
        match = rev_re.match(line.strip())
        if match:
            revisions.append(int(match.group(1)))
    max_r = max(revisions, default=0)

    clean_tag = (release_tag or "").strip()
    if publish_release:
        if clean_tag:
            if re.fullmatch(r"r[0-9]+(?:\.[0-9]+)*", clean_tag):
                tag = f"{base}-{clean_tag}"
            elif re.fullmatch(
                r"v[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9._-]+)?",
                clean_tag,
            ):
                tag = clean_tag
            else:
                raise ValueError(f"Invalid release tag: {clean_tag!r}")
        else:
            tag = f"{base}-r{max_r + 1}"
        version = tag
    else:
        tag = f"{base}-r{max(max_r, 1)}"
        version = f"{tag}-{short}"

    version_code = 20400 + int(run_number)
    return {
        "commit": commit,
        "base": base,
        "tag": tag,
        "version": version,
        "version_code": str(version_code),
        "is_release": "true" if publish_release else "false",
    }


def write_github_outputs(mapping):
    output_path = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{k}={v}\n" for k, v in mapping.items())
    if output_path:
        with open(output_path, "a", encoding="utf-8") as stream:
            stream.write(lines)
    print(lines, end="")


def download_modules(run, destination, selected, version):
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not run.isdecimal():
        raise ValueError("Invalid Actions context")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    base = f"repos/{repository}/actions/runs/{run}"
    metadata = json.loads(subprocess.check_output(["gh", "api", base]))
    if metadata["head_sha"] != commit:
        raise ValueError("Actions run does not match checked-out commit")
    assets = json.loads(
        subprocess.check_output(["gh", "api", base + "/artifacts?per_page=100"])
    )["artifacts"]
    destination.mkdir(parents=True, exist_ok=True)

    def fetch(kmi):
        name = f"{ARTIFACT_PREFIX}-{version}-{kmi}.ko"
        matching = [a for a in assets if a["name"] == name and not a["expired"]]
        if len(matching) != 1:
            raise ValueError(f"Missing or ambiguous artifact: {name}")
        raw = subprocess.check_output(
            ["gh", "api", f"repos/{repository}/actions/artifacts/{matching[0]['id']}/zip"]
        )
        if raw.startswith(b"PK"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if archive.namelist() != [name]:
                    raise ValueError(f"Unexpected artifact contents for {name}: {archive.namelist()}")
                raw = archive.read(name)
        (destination / name).write_bytes(raw)

    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        list(pool.map(fetch, selected))


def locate_ko(ko_dir, version, kmi):
    candidates = [
        ko_dir / f"{ARTIFACT_PREFIX}-{version}-{kmi}.ko",
        ko_dir / f"susfs_guard_lkm-{kmi}.ko",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(f"Missing .ko for {kmi} in {ko_dir}")


def package_zip(loader, ko_dir, output, requested, version_str, version_code, download_run=None):
    selected = list(KMIS) if requested == "universal" else [requested]
    if any(kmi not in KMIS for kmi in selected):
        raise ValueError(f"Unsupported KMI selection: {requested!r}")

    ko_dir = Path(ko_dir)
    if download_run:
        download_modules(download_run, ko_dir, selected, version_str)

    loader_data = Path(loader).read_bytes()
    check_loader(loader_data)

    low = min(selected, key=lambda k: tuple(int(n) for n in k.split("-", 1)[1].split("."))).split("-", 1)[1]
    high = max(selected, key=lambda k: tuple(int(n) for n in k.split("-", 1)[1].split("."))).split("-", 1)[1]

    files = {}
    for script in MODULE_SCRIPTS:
        files[script] = (ROOT / "module" / script).read_bytes().replace(b"\r\n", b"\n")
    files["LICENSE"] = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    files["kmis"] = ("\n".join(selected) + "\n").encode("utf-8")
    files["kmi_override"] = b""
    files["module.prop"] = (
        f"id={MODULE_ID}\n"
        f"name={MODULE_NAME}\n"
        f"version={version_str}\n"
        f"versionCode={version_code}\n"
        f"author={MODULE_AUTHOR}\n"
        f"description={MODULE_NAME} ({len(selected)} arm64 KMIs, {low}-{high}) - not loaded yet.\n"
    ).encode("utf-8")
    files["bin/susfs_insmod"] = loader_data

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for kmi in selected:
        ko_path = locate_ko(ko_dir, version_str, kmi)
        data = ko_path.read_bytes()
        check_ko(data, kmi, expected_version=version_str)
        files[f"lib/susfs_guard_lkm-{kmi}.ko"] = data
        (output / f"{ARTIFACT_PREFIX}-{version_str}-{kmi}.ko").write_bytes(data)

    if requested == "universal":
        zip_name = f"{ARTIFACT_PREFIX}-{version_str}.zip"
    else:
        zip_name = f"{ARTIFACT_PREFIX}-{version_str}-{selected[0]}.zip"
    zip_path = output / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 11, 14, 0, 0, 0))
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (
                0o100755 if name.endswith(".sh") or name.startswith("bin/") else 0o100644
            ) << 16
            archive.writestr(entry, data)

    with zipfile.ZipFile(zip_path) as archive:
        if archive.testzip() or set(archive.namelist()) != set(files):
            raise ValueError("Invalid ZIP integrity check")
        for name, data in files.items():
            if archive.read(name) != data:
                raise ValueError(f"ZIP entry mismatch: {name}")

    print(f"Created {zip_path} ({len(files)} entries, {len(selected)} KMIs)")
    write_github_outputs({"zip_name": zip_name, "zip_path": str(zip_path)})

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(
                f"### {MODULE_NAME} (`{version_str}` / `{requested}`)\n"
                f"- ZIP: `{zip_name}`\n"
                f"- KMIs: {', '.join(f'`{k}`' for k in selected)}\n\n"
            )
    return zip_path


def main():
    parser = argparse.ArgumentParser(description="SusFS LKM by uran build & packaging tool")
    parser.add_argument("--resolve", action="store_true", help="Resolve CI/release version outputs")
    parser.add_argument("--publish-release", action="store_true")
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--run-number", type=int, default=int(os.environ.get("GITHUB_RUN_NUMBER", "0")))

    parser.add_argument("--verify-ko", help="Verify a single compiled .ko file")
    parser.add_argument("--kmi", help="Target KMI for --verify-ko")
    parser.add_argument("--expected-version", help="Expected MODULE_VERSION for --verify-ko or --package")

    parser.add_argument("--package", action="store_true", help="Package KernelSU ZIP + artifacts")
    parser.add_argument("--loader", help="Path to compiled susfs_insmod binary")
    parser.add_argument("--ko-dir", help="Directory containing compiled .ko modules")
    parser.add_argument("--download-run", help="GitHub Actions run id to download .ko artifacts from")
    parser.add_argument("--kernel", choices=("universal",) + KMIS, default="universal")
    parser.add_argument("--version-code", default="20400")
    parser.add_argument("--output", default=str(ROOT / "dist"))
    args = parser.parse_args()

    if args.resolve:
        pub = args.publish_release or os.environ.get("PUBLISH_RELEASE", "").lower() == "true"
        tag = args.release_tag or os.environ.get("RELEASE_TAG", "")
        write_github_outputs(resolve_version(pub, tag, args.run_number))
        return

    if args.verify_ko:
        if not args.kmi:
            parser.error("--kmi is required with --verify-ko")
        check_ko(Path(args.verify_ko).read_bytes(), args.kmi, expected_version=args.expected_version)
        print(f"Verified {args.verify_ko} ({args.kmi}, version={args.expected_version})")
        return

    if args.package:
        if not args.loader or not args.ko_dir:
            parser.error("--loader and --ko-dir are required with --package")
        ver = args.expected_version or resolve_version(run_number=args.run_number)["version"]
        package_zip(
            loader=args.loader,
            ko_dir=args.ko_dir,
            output=args.output,
            requested=args.kernel,
            version_str=ver,
            version_code=args.version_code,
            download_run=args.download_run,
        )
        return

    parser.error("Specify one of --resolve, --verify-ko, or --package")


if __name__ == "__main__":
    main()
