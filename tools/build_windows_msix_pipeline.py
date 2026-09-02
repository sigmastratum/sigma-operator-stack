#!/usr/bin/env python3
"""Run two exact MakeAppx pack/unpack cycles and freeze one admitted MSIX."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def _load_source_verifier():
    path = Path(__file__).with_name("verify_windows_msix_source.py")
    spec = importlib.util.spec_from_file_location("_sos_msix_source_verifier", path)
    if spec is None or spec.loader is None:
        raise SystemExit("exact source verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


source_verifier = _load_source_verifier()


OUTPUT_NAME = "SigmaOperatorStack_1.0.4.0_x64.msix"
MAX_DIAGNOSTIC_BYTES = 512 * 1024
BUILDER_KEYS = {
    "candidate",
    "contract",
    "makeappx_sha256",
    "msix_sha256",
    "msix_version",
    "package_family_name",
    "package_identity_name",
    "payload_file_count",
    "payload_tree_digest",
    "source_manifest_sha256",
    "source_tree_digest",
    "stage_file_count",
    "stage_tree_digest",
    "status",
    "store_id",
    "tree",
}
COMPARISON_KEYS = {
    "byte_identical",
    "candidate",
    "container_equivalence_claimed",
    "contract",
    "first_msix_sha256",
    "makeappx_sha256",
    "package_content_digest",
    "package_file_count",
    "payload_file_count",
    "pyc_file_count",
    "raw_content_serialized",
    "second_msix_sha256",
    "status",
    "tree",
    "verification_method",
}
CONTENT_SAFETY_KEYS = {
    "absolute_paths_serialized",
    "candidate",
    "contract",
    "opaque_bound_file_count",
    "package_content_digest",
    "package_file_count",
    "payload_file_count",
    "raw_content_serialized",
    "report_digest",
    "scanned_text_file_count",
    "status",
    "tree",
}


class PipelineError(ValueError):
    """The exact Windows package pipeline cannot continue."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def closed_environment() -> dict[str, str]:
    blocked = {
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONINSPECT",
        "PYTHONPYCACHEPREFIX",
    }
    environment = {
        key: value for key, value in os.environ.items() if key.upper() not in blocked
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    return environment


def run_phase(
    phase: str,
    command: list[str],
    timeout: int = 600,
    *,
    capture_stdout: bool = True,
) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=closed_environment(),
        )
    except subprocess.TimeoutExpired as error:
        raise PipelineError(f"{phase} timed out") from error
    stdout = completed.stdout if completed.stdout is not None else b""
    if len(stdout) > MAX_DIAGNOSTIC_BYTES or len(completed.stderr) > MAX_DIAGNOSTIC_BYTES:
        raise PipelineError(f"{phase} output exceeded the bounded limit")
    if completed.returncode != 0:
        diagnostic_digest = hashlib.sha256(completed.stderr).hexdigest()
        try:
            lines = completed.stderr.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            lines = []
        last = lines[-1] if lines else ""
        if not re.fullmatch(r"SOS_[A-Z0-9_]+: [A-Za-z0-9 .,_-]+", last):
            last = f"diagnostic_sha256={diagnostic_digest}"
        raise PipelineError(
            f"{phase} failed with exit {completed.returncode}; {last}"
        )
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PipelineError(f"{phase} output was not UTF-8") from error


def exact_makeappx(
    makeappx: Path,
    expected_digest: str,
    phase: str,
    arguments: list[str],
) -> str:
    before = sha256(makeappx)
    if before != expected_digest:
        raise PipelineError(f"MakeAppx digest drifted before {phase}")
    # MakeAppx emits one success line per payload entry.  The immutable Python
    # runtime contains enough entries to exceed the diagnostic bound, while
    # callers never consume successful MakeAppx stdout.  Discard it at the OS
    # pipe boundary; stderr remains bounded and non-zero exits still fail.
    output = run_phase(
        phase,
        [os.fspath(makeappx), *arguments],
        capture_stdout=False,
    )
    if sha256(makeappx) != before:
        raise PipelineError(f"MakeAppx digest drifted during {phase}")
    return output


def validate_builder_receipt(
    record: object,
    candidate: str,
    tree: str,
    makeappx_sha256: str,
    source_manifest_sha256: str,
    source_tree_digest: str,
    package: Path,
) -> dict[str, object]:
    if not isinstance(record, dict) or set(record) != BUILDER_KEYS:
        raise PipelineError("builder receipt contract is invalid")
    if (
        record["contract"] != "sos_windows_unsigned_msix_build_v1"
        or record["status"] != "passed"
        or record["candidate"] != candidate
        or record["tree"] != tree
        or record["makeappx_sha256"] != makeappx_sha256
        or record["msix_sha256"] != sha256(package)
        or record["msix_version"] != "1.0.4.0"
        or record["package_identity_name"] != "SSRG.SigmaOperatorStack"
        or record["store_id"] != "9NNZT70C613H"
        or record["source_manifest_sha256"] != f"sha256:{source_manifest_sha256}"
        or record["source_tree_digest"] != f"sha256:{source_tree_digest}"
    ):
        raise PipelineError("builder receipt binding is invalid")
    for key in ("payload_tree_digest", "stage_tree_digest"):
        if not isinstance(record[key], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", record[key]
        ):
            raise PipelineError("builder receipt digest is invalid")
    for key in ("payload_file_count", "stage_file_count"):
        if not isinstance(record[key], int) or isinstance(record[key], bool) or record[key] <= 0:
            raise PipelineError("builder receipt count is invalid")
    return record


def validate_comparison_receipt(
    record: object,
    candidate: str,
    tree: str,
    makeappx_sha256: str,
    first: Path,
    second: Path,
) -> dict[str, object]:
    if not isinstance(record, dict) or set(record) != COMPARISON_KEYS:
        raise PipelineError("semantic comparison receipt contract is invalid")
    if (
        record["contract"] != "sos_windows_msix_semantic_comparison_v2"
        or record["status"] != "passed"
        or record["candidate"] != candidate
        or record["tree"] != tree
        or record["makeappx_sha256"] != f"sha256:{makeappx_sha256}"
        or record["first_msix_sha256"] != f"sha256:{sha256(first)}"
        or record["second_msix_sha256"] != f"sha256:{sha256(second)}"
        or record["container_equivalence_claimed"] is not False
        or record["raw_content_serialized"] is not False
        or record["pyc_file_count"] != 0
        or record["verification_method"]
        != "default_makeappx_unpack_exact_content_v1"
    ):
        raise PipelineError("semantic comparison receipt binding is invalid")
    if not isinstance(record["package_content_digest"], str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", record["package_content_digest"]
    ):
        raise PipelineError("semantic comparison digest is invalid")
    for key in ("package_file_count", "payload_file_count"):
        if not isinstance(record[key], int) or isinstance(record[key], bool) or record[key] <= 0:
            raise PipelineError("semantic comparison count is invalid")
    return record


def validate_content_safety_receipt(
    record: object,
    candidate: str,
    tree: str,
) -> dict[str, object]:
    if not isinstance(record, dict) or set(record) != CONTENT_SAFETY_KEYS:
        raise PipelineError("content-safety receipt contract is invalid")
    if (
        record["contract"] != "sos_windows_msix_content_safety_v1"
        or record["status"] != "passed"
        or record["candidate"] != candidate
        or record["tree"] != tree
        or record["absolute_paths_serialized"] is not False
        or record["raw_content_serialized"] is not False
    ):
        raise PipelineError("content-safety receipt binding is invalid")
    for key in ("package_content_digest", "report_digest"):
        if not isinstance(record[key], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", record[key]
        ):
            raise PipelineError("content-safety receipt digest is invalid")
    for key in (
        "opaque_bound_file_count",
        "package_file_count",
        "payload_file_count",
        "scanned_text_file_count",
    ):
        if (
            not isinstance(record[key], int)
            or isinstance(record[key], bool)
            or record[key] < 0
        ):
            raise PipelineError("content-safety receipt count is invalid")
    if (
        record["package_file_count"] <= 0
        or record["payload_file_count"] <= 0
        or record["payload_file_count"] > record["package_file_count"]
        or record["scanned_text_file_count"] <= 0
        or record["opaque_bound_file_count"] + record["scanned_text_file_count"]
        != record["package_file_count"]
    ):
        raise PipelineError("content-safety receipt counts are inconsistent")
    body = dict(record)
    report_digest = body.pop("report_digest")
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if report_digest != f"sha256:{expected}":
        raise PipelineError("content-safety report digest is invalid")
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--payload-root", required=True, type=Path)
    parser.add_argument("--makeappx", required=True, type=Path)
    parser.add_argument("--makeappx-sha256", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate):
        raise PipelineError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.tree):
        raise PipelineError("tree binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", args.makeappx_sha256):
        raise PipelineError("MakeAppx binding is invalid")
    for supplied, kind in (
        (args.source_root, "source"),
        (args.source_manifest, "source manifest"),
        (args.payload_root, "payload"),
        (args.makeappx, "MakeAppx"),
    ):
        supplied_stat = supplied.lstat()
        attributes = getattr(supplied_stat, "st_file_attributes", 0)
        if stat.S_ISLNK(supplied_stat.st_mode) or attributes & 0x400:
            raise PipelineError(f"{kind} path is a link or reparse object")
    if args.output_root.exists():
        output_stat = args.output_root.lstat()
        if stat.S_ISLNK(output_stat.st_mode) or getattr(
            output_stat, "st_file_attributes", 0
        ) & 0x400:
            raise PipelineError("output root is a link or reparse object")
    source_root = args.source_root.resolve(strict=True)
    source_manifest = args.source_manifest.resolve(strict=True)
    payload = args.payload_root.resolve(strict=True)
    makeappx = args.makeappx.resolve(strict=True)
    output_root = args.output_root.resolve()
    if (
        source_root == payload
        or source_root in payload.parents
        or payload in source_root.parents
    ):
        raise PipelineError("payload root must be external to the source snapshot")
    if (
        output_root == source_root
        or source_root in output_root.parents
        or output_root in source_root.parents
    ):
        raise PipelineError("output root must be external to the source snapshot")
    if (
        output_root == payload
        or payload in output_root.parents
        or output_root in payload.parents
    ):
        raise PipelineError("output root must be external to the payload")
    if source_manifest == payload or payload in source_manifest.parents:
        raise PipelineError("source manifest must be external to the payload")
    if output_root == source_manifest or output_root in source_manifest.parents:
        raise PipelineError("output root must be external to the source manifest")
    if output_root.exists() and not output_root.is_dir():
        raise PipelineError("output root is not a plain directory")
    output_root.mkdir(parents=True, exist_ok=True)
    final = output_root / OUTPUT_NAME
    comparison_receipt = output_root / "msix-comparison.json"
    first_build_receipt = output_root / "first-build.json"
    second_build_receipt = output_root / "second-build.json"
    first_content_receipt = output_root / "first-content-safety.json"
    second_content_receipt = output_root / "second-content-safety.json"
    result_path = output_root / "build-result.json"
    if any(
        path.exists()
        for path in (
            final,
            comparison_receipt,
            first_build_receipt,
            second_build_receipt,
            first_content_receipt,
            second_content_receipt,
            result_path,
        )
    ):
        raise PipelineError("final output already exists")

    baseline = source_verifier.verify_source_snapshot(
        source_root,
        source_manifest,
        args.candidate,
        args.tree,
    )
    for relative, local_path in (
        ("tools/build_windows_msix_pipeline.py", Path(__file__)),
        ("tools/verify_windows_msix_source.py", Path(source_verifier.__file__)),
    ):
        if sha256(local_path) != baseline.artifact(relative).sha256:
            raise PipelineError("executing source tool is not bound to the exact snapshot")

    def reverify_source() -> None:
        source_verifier.same_snapshot(
            baseline,
            source_verifier.verify_source_snapshot(
                source_root,
                source_manifest,
                args.candidate,
                args.tree,
            ),
        )

    with tempfile.TemporaryDirectory(prefix="sos-msix-pipeline-") as temporary:
        root = Path(temporary)
        reviewed_tools = root / "reviewed-tools"
        reviewed_tools.mkdir()
        builder = reviewed_tools / "build_windows_msix.py"
        comparator = reviewed_tools / "compare_windows_msix.py"
        content_checker = reviewed_tools / "check_windows_msix_content.py"
        verifier = reviewed_tools / "verify_windows_msix_source.py"
        for relative, destination in (
            ("tools/build_windows_msix.py", builder),
            ("tools/compare_windows_msix.py", comparator),
            ("tools/check_windows_msix_content.py", content_checker),
            ("tools/verify_windows_msix_source.py", verifier),
        ):
            blob = source_verifier.read_bound_source_file(
                source_root,
                baseline,
                relative,
            )
            if not blob:
                raise PipelineError("reviewed pipeline tool is missing")
            destination.write_bytes(blob)
        reverify_source()
        first = root / "first.msix"
        second = root / "second.msix"
        first_unpacked = root / "first-unpacked"
        second_unpacked = root / "second-unpacked"
        first_unpacked.mkdir()
        second_unpacked.mkdir()
        common = [
            "--source-root",
            os.fspath(source_root),
            "--source-manifest",
            os.fspath(source_manifest),
            "--candidate",
            args.candidate,
            "--tree",
            args.tree,
            "--payload-root",
            os.fspath(payload),
            "--makeappx",
            os.fspath(makeappx),
            "--makeappx-sha256",
            args.makeappx_sha256,
            "--output",
        ]
        reverify_source()
        first_build = run_phase(
            "first pack preparation",
            [sys.executable, "-I", "-B", os.fspath(builder), *common, os.fspath(first)],
        )
        reverify_source()
        reverify_source()
        second_build = run_phase(
            "second pack preparation",
            [sys.executable, "-I", "-B", os.fspath(builder), *common, os.fspath(second)],
        )
        reverify_source()
        try:
            first_build_record = json.loads(first_build)
            second_build_record = json.loads(second_build)
        except json.JSONDecodeError as error:
            raise PipelineError("builder receipt is invalid") from error
        first_build_record = validate_builder_receipt(
            first_build_record,
            args.candidate,
            args.tree,
            args.makeappx_sha256,
            baseline.manifest_sha256,
            baseline.source_tree_digest,
            first,
        )
        second_build_record = validate_builder_receipt(
            second_build_record,
            args.candidate,
            args.tree,
            args.makeappx_sha256,
            baseline.manifest_sha256,
            baseline.source_tree_digest,
            second,
        )
        if first_build_record["payload_tree_digest"] != second_build_record[
            "payload_tree_digest"
        ] or first_build_record["stage_tree_digest"] != second_build_record[
            "stage_tree_digest"
        ]:
            raise PipelineError("independent pack inputs differ")

        first_before = sha256(first)
        reverify_source()
        exact_makeappx(
            makeappx,
            args.makeappx_sha256,
            "first default unpack",
            ["unpack", "/o", "/p", os.fspath(first), "/d", os.fspath(first_unpacked)],
        )
        if sha256(first) != first_before:
            raise PipelineError("first package changed during unpack")
        reverify_source()
        second_before = sha256(second)
        reverify_source()
        exact_makeappx(
            makeappx,
            args.makeappx_sha256,
            "second default unpack",
            ["unpack", "/o", "/p", os.fspath(second), "/d", os.fspath(second_unpacked)],
        )
        if sha256(second) != second_before:
            raise PipelineError("second package changed during unpack")
        reverify_source()

        content_records: list[dict[str, object]] = []
        for phase, unpacked in (
            ("first content-safety scan", first_unpacked),
            ("second content-safety scan", second_unpacked),
        ):
            reverify_source()
            content_output = run_phase(
                phase,
                [
                    sys.executable,
                    "-I",
                    "-B",
                    os.fspath(content_checker),
                    "--unpacked-root",
                    os.fspath(unpacked),
                    "--candidate",
                    args.candidate,
                    "--tree",
                    args.tree,
                ],
            )
            reverify_source()
            try:
                content_record = json.loads(content_output)
            except json.JSONDecodeError as error:
                raise PipelineError("content-safety receipt is invalid") from error
            content_records.append(
                validate_content_safety_receipt(
                    content_record,
                    args.candidate,
                    args.tree,
                )
            )

        reverify_source()
        comparison = run_phase(
            "semantic comparison",
            [
                sys.executable,
                "-I",
                "-B",
                os.fspath(comparator),
                os.fspath(first),
                os.fspath(second),
                "--first-unpacked",
                os.fspath(first_unpacked),
                "--second-unpacked",
                os.fspath(second_unpacked),
                "--candidate",
                args.candidate,
                "--tree",
                args.tree,
                "--makeappx-sha256",
                args.makeappx_sha256,
            ],
        )
        reverify_source()
        try:
            comparison_record = json.loads(comparison)
        except json.JSONDecodeError as error:
            raise PipelineError("semantic comparison receipt is invalid") from error
        comparison_record = validate_comparison_receipt(
            comparison_record,
            args.candidate,
            args.tree,
            args.makeappx_sha256,
            first,
            second,
        )
        if content_records[0] != content_records[1]:
            raise PipelineError("independent content-safety receipts differ")
        if any(
            record["package_content_digest"]
            != comparison_record["package_content_digest"]
            for record in content_records
        ):
            raise PipelineError("content-safety and semantic receipts disagree")

        reverify_source()
        for relative, destination in (
            ("tools/build_windows_msix.py", builder),
            ("tools/compare_windows_msix.py", comparator),
            ("tools/check_windows_msix_content.py", content_checker),
            ("tools/verify_windows_msix_source.py", verifier),
        ):
            current_blob = source_verifier.read_bound_source_file(
                source_root,
                baseline,
                relative,
            )
            if destination.read_bytes() != current_blob:
                raise PipelineError("reviewed pipeline tool drifted")
        reverify_source()

        shutil.copyfile(first, final)
        if sha256(final) != first_before:
            raise PipelineError("final package copy digest mismatch")
        for path, record in (
            (first_build_receipt, first_build_record),
            (second_build_receipt, second_build_record),
            (first_content_receipt, content_records[0]),
            (second_content_receipt, content_records[1]),
            (comparison_receipt, comparison_record),
        ):
            path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
                newline="",
            )
        result = {
            "candidate": args.candidate,
            "comparison_receipt_sha256": f"sha256:{sha256(comparison_receipt)}",
            "contract": "sos_windows_store_msix_build_result_v2",
            "first_build_receipt_sha256": f"sha256:{sha256(first_build_receipt)}",
            "first_content_safety_receipt_sha256": f"sha256:{sha256(first_content_receipt)}",
            "makeappx_sha256": f"sha256:{args.makeappx_sha256}",
            "msix_sha256": f"sha256:{sha256(final)}",
            "network_phase": "none",
            "package_content_digest": comparison_record["package_content_digest"],
            "package_identity_name": "SSRG.SigmaOperatorStack",
            "status": "passed",
            "store_id": "9NNZT70C613H",
            "second_build_receipt_sha256": f"sha256:{sha256(second_build_receipt)}",
            "second_content_safety_receipt_sha256": f"sha256:{sha256(second_content_receipt)}",
            "source_manifest_sha256": f"sha256:{baseline.manifest_sha256}",
            "source_tree_digest": f"sha256:{baseline.source_tree_digest}",
            "tree": args.tree,
            "verification_method": "two_pack_two_default_unpack_exact_content_v1",
        }
        result_path.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="",
        )
        reverify_source()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PipelineError, OSError) as error:
        print(f"SOS_MSIX_PIPELINE_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
