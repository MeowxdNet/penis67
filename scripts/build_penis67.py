#!/usr/bin/env python3
"""Builds the penis67 plugin module (same pipeline as the nowhere plugin)."""
from pathlib import Path
import argparse, json, os, subprocess, sys, zipfile

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ.get("ANDROID_HOME", str(Path.home() / "Android/Sdk")))
NDK = Path(os.environ.get("ANDROID_NDK_HOME", str(SDK / "ndk/28.2.13676358")))
BIN = NDK / "toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT = ROOT / "build/penis67-plugin"

ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
TRIPLES = {"arm64-v8a": "aarch64-linux-android", "armeabi-v7a": "armv7a-linux-androideabi",
           "x86_64": "x86_64-linux-android", "x86": "i686-linux-android"}
GOARCH = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "amd64", "x86": "386"}
API = 26


def build_android(abi: str, out: Path) -> None:
    env = os.environ.copy()
    env.update(CGO_ENABLED="1", GOOS="android", GOARCH=GOARCH[abi],
               CC=str(BIN / f"{TRIPLES[abi]}{API}-clang"),
               CGO_LDFLAGS="-Wl,-z,max-page-size=16384")
    subprocess.run(["go", "build", "-buildmode=c-shared", "-trimpath",
                    "-ldflags", "-s -w -buildid=", "-o", str(out), "."],
                   cwd=ROOT, env=env, check=True)
    print(f"built {abi}: {out.stat().st_size} bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("abis", nargs="*", default=["arm64-v8a"])
    parser.add_argument("--desktop", action="store_true")
    args = parser.parse_args()
    abis = args.abis or ["arm64-v8a"]
    stage = OUT / "stage"
    stage.mkdir(parents=True, exist_ok=True)
    for stale in stage.glob("penis67-plugin-*"):
        stale.unlink()
    helpers = {}
    for abi in abis:
        so = stage / f"penis67-plugin-{abi}.so"
        build_android(abi, so)
        header = so.with_suffix(".h")
        if header.exists():
            header.unlink()
        helpers[abi] = so.name
    manifest = json.loads((ROOT / "module.json").read_text())
    manifest["helperBinary"]["android"] = helpers[abis[0]]
    manifest["helperBinary"]["desktop"] = helpers[abis[0]]
    (stage / "module.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    if args.desktop:
        desktop = stage / "penis67-plugin-desktop"
        env = os.environ.copy(); env["CGO_ENABLED"] = "0"
        subprocess.run(["go", "build", "-trimpath", "-ldflags", "-s -w -buildid=",
                        "-o", str(desktop), "."], cwd=ROOT, env=env, check=True)
        manifest = json.loads((stage / "module.json").read_text())
        manifest["helperBinary"]["desktop"] = desktop.name
        (stage / "module.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    archive = OUT / f"penis67-plugin-{abis[0]}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(stage.iterdir()):
            zf.write(path, path.name)
    print(f"packaged {archive} ({archive.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
