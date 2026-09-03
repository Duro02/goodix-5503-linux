"""Interactive, fail-closed setup for the Goodix 27c6:5503 pairing state.

Normal execution runs as the desktop user and delegates four fixed helpers through
sudo.  Package installation never writes the sensor.  A new pairing is created
only after an explicit warning/confirmation, with one fixed write and immediate
readback.  No helper accepts a raw command, selector, payload, or secret value.
"""

from __future__ import annotations

import argparse
import hmac
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

from .pairing import PROJECT_ROOT, PSK_PATH, calculate_r_verification_record, prepare_pairing
from .probe import (
    COMMAND_FIRMWARE_VERSION,
    COMMAND_GET_IAP_VERSION,
    COMMAND_NOP,
    ReadOnlyUsbSession,
    _decode_c_string,
    probe,
)
from .provision import (
    EXPECTED_FIRMWARE,
    EXPECTED_IAP,
    WRITE_CONFIRMATION,
    _read_live_verification,
    provision_prepared_pairing,
)
from .security import disable_core_dumps
from .whitebox import WhiteboxError, find_pinned_wbdi

SYSTEM_PSK_PATH: Final = Path("/var/lib/fprint/goodix5503/psk.bin")
USER_CONFIRMATION: Final = "REPLACE WINDOWS PAIRING"
_ROOT_MODES: Final = {
    "--root-check",
    "--root-backup",
    "--root-provision",
    "--root-install",
}


class SetupError(RuntimeError):
    """The public setup flow could not complete safely."""


def _sudo_identity() -> tuple[int, int]:
    if os.geteuid() != 0:
        raise SetupError("fixed setup helper requires sudo root")
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError) as error:
        raise SetupError("run the fixed setup helper through sudo") from error
    if uid <= 0 or gid < 0:
        raise SetupError("invalid sudo user identity")
    return uid, gid


def _read_exact_secure_file(
    path: Path, expected_length: int, *, expected_uid: int
) -> bytearray:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    result = bytearray(expected_length)
    extra = bytearray(1)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != expected_length
        ):
            raise SetupError(f"unsafe secret file: {path}")
        view = memoryview(result)
        offset = 0
        while offset < len(view):
            count = os.readv(descriptor, [view[offset:]])
            if count <= 0:
                raise SetupError(f"short secret read: {path}")
            offset += count
        if os.readv(descriptor, [extra]) != 0:
            raise SetupError(f"trailing secret data: {path}")
        return result
    except BaseException:
        result[:] = b"\x00" * len(result)
        raise
    finally:
        extra[:] = b"\x00"
        os.close(descriptor)


def _root_check() -> dict[str, str]:
    """Read-only device/host pairing check; never creates or changes state."""
    _sudo_identity()
    disable_core_dumps()
    live = bytearray()
    host = bytearray()
    derived = bytearray()
    try:
        with ReadOnlyUsbSession() as session:
            session.request(COMMAND_NOP, checksum=False)
            firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))
            iap = _decode_c_string(
                session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00")
            )
            if firmware != EXPECTED_FIRMWARE or iap != EXPECTED_IAP:
                raise SetupError(
                    f"unsupported firmware/IAP: {firmware!r} / {iap!r}"
                )
            live = _read_live_verification(session)
        try:
            host = _read_exact_secure_file(SYSTEM_PSK_PATH, 32, expected_uid=0)
        except FileNotFoundError:
            return {
                "firmware": firmware,
                "iap": iap,
                "pairing": "host-psk-missing",
            }
        derived = calculate_r_verification_record(host)
        return {
            "firmware": firmware,
            "iap": iap,
            "pairing": (
                "matched" if hmac.compare_digest(live, derived) else "mismatched"
            ),
        }
    finally:
        live[:] = b"\x00" * len(live)
        host[:] = b"\x00" * len(host)
        derived[:] = b"\x00" * len(derived)


def _root_backup() -> dict[str, object]:
    _sudo_identity()
    result = probe(backup_rollback_set=True)
    return {
        "firmware": result.firmware,
        "iap": result.iap,
        "rollback_set": result.rollback_set,
    }


def _root_provision(confirmation: str | None) -> dict[str, str]:
    _sudo_identity()
    if confirmation != WRITE_CONFIRMATION:
        raise SetupError("exact provisioning confirmation was not supplied")
    return provision_prepared_pairing(confirmation=confirmation)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prepared_pairing_exists() -> bool:
    """Treat any existing prepared-key path as resume state to validate."""
    try:
        PSK_PATH.lstat()
    except FileNotFoundError:
        return False
    return True


def _root_install() -> dict[str, str]:
    """Atomically install only the prepared PSK after provisioning/readback."""
    source_uid, _source_gid = _sudo_identity()
    disable_core_dumps()
    secret = bytearray()
    existing = bytearray()
    target_directory = SYSTEM_PSK_PATH.parent
    temporary: Path | None = None
    descriptor = -1
    try:
        secret = _read_exact_secure_file(PSK_PATH, 32, expected_uid=source_uid)
        expected_live = calculate_r_verification_record(secret)
        try:
            with ReadOnlyUsbSession() as session:
                live = _read_live_verification(session)
            try:
                if not hmac.compare_digest(live, expected_live):
                    raise SetupError(
                        "refusing host PSK install before exact device readback"
                    )
            finally:
                live[:] = b"\x00" * len(live)
        finally:
            expected_live[:] = b"\x00" * len(expected_live)
        parent_info = target_directory.parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != 0
        ):
            raise SetupError("unsafe system PSK parent directory")
        try:
            target_directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            _fsync_directory(target_directory.parent)
        directory_info = target_directory.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_ISLNK(directory_info.st_mode)
            or directory_info.st_uid != 0
        ):
            raise SetupError("unsafe system PSK directory")
        os.chown(target_directory, 0, 0)
        os.chmod(target_directory, 0o700)

        try:
            target_info = SYSTEM_PSK_PATH.lstat()
        except FileNotFoundError:
            target_info = None
        if target_info is not None:
            if (
                stat.S_ISLNK(target_info.st_mode)
                or not stat.S_ISREG(target_info.st_mode)
                or target_info.st_uid != 0
                or target_info.st_gid != 0
                or target_info.st_nlink != 1
                or stat.S_IMODE(target_info.st_mode) != 0o600
                or target_info.st_size != 32
            ):
                raise SetupError("refusing to replace unsafe system PSK state")
            existing = _read_exact_secure_file(
                SYSTEM_PSK_PATH, 32, expected_uid=0
            )
            if hmac.compare_digest(existing, secret):
                return {"host_psk": "verified-existing"}

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".psk.bin.new-", dir=target_directory
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        view = memoryview(secret)
        offset = 0
        while offset < len(view):
            count = os.write(descriptor, view[offset:])
            if count <= 0:
                raise SetupError("short system PSK write")
            offset += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, SYSTEM_PSK_PATH)
        temporary = None
        _fsync_directory(target_directory)
        installed = _read_exact_secure_file(SYSTEM_PSK_PATH, 32, expected_uid=0)
        try:
            if not hmac.compare_digest(installed, secret):
                raise SetupError("installed system PSK verification failed")
        finally:
            installed[:] = b"\x00" * len(installed)
        return {
            "host_psk": "installed" if target_info is None else "replaced"
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        secret[:] = b"\x00" * len(secret)
        existing[:] = b"\x00" * len(existing)


def _root_command(mode: str) -> list[str]:
    if mode not in _ROOT_MODES:
        raise SetupError("invalid fixed root helper mode")
    command = ["sudo", "--", sys.executable, "-B", "-m", "goodix5503.setup", mode]
    if mode == "--root-provision":
        command.extend(["--write-confirmation", WRITE_CONFIRMATION])
    return command


def _run_json(command: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=None,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SetupError("fixed setup helper returned invalid output") from error
    if not isinstance(result, dict):
        raise SetupError("fixed setup helper returned invalid result")
    return result


def _service(command: str) -> None:
    subprocess.run(
        ["sudo", "systemctl", command, "fprintd.service"],
        check=True,
    )


def setup_pairing() -> dict[str, object]:
    """Check existing state or explicitly establish one new pairing."""
    if os.geteuid() == 0:
        raise SetupError("run goodix-5503-setup as the desktop user, not sudo")
    disable_core_dumps()
    stopped = False
    pending_error: BaseException | None = None
    try:
        _service("stop")
        stopped = True
        initial = _run_json(_root_command("--root-check"))
        if initial.get("pairing") == "matched":
            return {
                "operation": "already-paired-no-write",
                "pairing": "matched",
            }

        try:
            find_pinned_wbdi(PROJECT_ROOT)
            if importlib.util.find_spec("unicorn") is None:
                raise WhiteboxError("the optional Unicorn dependency is missing")
        except WhiteboxError as error:
            raise SetupError(
                f"{error}. Download/extract the pinned Lenovo driver with "
                "scripts/download-windows-drivers.sh and "
                "scripts/extract-windows-drivers.sh, then install the "
                "whitebox extra: pip install -e '.[whitebox]'"
            ) from error

        print(
            "WARNING: this will replace the sensor PSK. Existing Windows "
            "fingerprint pairing will stop working. Firmware is not changed.",
            file=sys.stderr,
        )
        answer = input(f"Type {USER_CONFIRMATION!r} to continue: ")
        if answer != USER_CONFIRMATION:
            raise SetupError("pairing replacement was not confirmed")

        resuming = _prepared_pairing_exists()
        if resuming:
            backup: dict[str, object] = {"operation": "preserved-existing-backup"}
            prepared = prepare_pairing()
        else:
            backup = _run_json(_root_command("--root-backup"))
            prepared = prepare_pairing()
        provisioned = _run_json(_root_command("--root-provision"))
        installed = _run_json(_root_command("--root-install"))
        final = _run_json(_root_command("--root-check"))
        if final.get("pairing") != "matched":
            raise SetupError("final host/device pairing verification failed")
        return {
            "operation": "pairing-ready",
            "backup": backup,
            "prepared": prepared,
            "provisioned": provisioned,
            "installed": installed,
            "pairing": "matched",
        }
    except BaseException as error:
        pending_error = error
        raise
    finally:
        if stopped:
            try:
                _service("restart")
            except BaseException as restart_error:
                if pending_error is None:
                    raise
                pending_error.add_note(
                    f"also failed to restart fprintd.service: {restart_error}"
                )


def _dispatch_root_mode(
    mode: str, *, write_confirmation: str | None
) -> dict[str, object]:
    if mode == "--root-provision":
        return _root_provision(write_confirmation)
    if write_confirmation is not None:
        raise SetupError("write confirmation is valid only for provisioning")
    return {
        "--root-check": _root_check,
        "--root-backup": _root_backup,
        "--root-install": _root_install,
    }[mode]()


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        description="Check or explicitly establish Goodix 5503 PSK pairing"
    )
    parser.add_argument("--write-confirmation", help=argparse.SUPPRESS)
    for mode in sorted(_ROOT_MODES):
        parser.add_argument(mode, action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    selected = [mode for mode in _ROOT_MODES if getattr(args, mode[2:].replace("-", "_"))]
    try:
        if selected:
            if len(selected) != 1:
                raise SetupError("invalid fixed helper invocation")
            result = _dispatch_root_mode(
                selected[0], write_confirmation=args.write_confirmation
            )
        else:
            if args.write_confirmation is not None:
                raise SetupError("invalid public setup invocation")
            result = setup_pairing()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (RuntimeError, OSError, EOFError, subprocess.CalledProcessError) as error:
        print(f"goodix-5503-setup: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"goodix-5503-setup: note: {note}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
