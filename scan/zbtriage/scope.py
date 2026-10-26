"""Shared scope controls for the package and standalone entry points."""
import os
import sys

from .localpaths import path_problem
from .contract import sanitize_untrusted


def scope_arguments(parser):
    parser.add_argument("--scan-type", choices=("default", "full", "targeted", "browser"),
                        default="default", help="full includes app caches and all file extensions in the usual roots; targeted reads only selected targets; browser reads only this account's browser profiles")
    parser.add_argument("--target", action="append", default=[], metavar="PATH",
                        help="local file, directory, drive or browser profile (repeatable; requires targeted)")
    parser.add_argument("--preview", action="store_true", help="show scope and phone artifact availability as JSON, without scanning")
    parser.add_argument("--collect-android", metavar="DIR", help="separate guided acquisition: download and verify a pinned official AndroidQF release, collect with owner consent, then check the plaintext collection")
    parser.add_argument("--age-recipient-file", metavar="PATH", help="public age1 recipients for --collect-android; encrypted acquisitions are saved for separate analysis")
    parser.add_argument("--phone-guide", choices=("android", "ios"), help="print local-backup preparation instructions and exit")
    parser.add_argument("--backup-password", action="store_true", help="prompt privately for an encrypted phone backup password; never pass the password on the command line")
    parser.add_argument("--ios-input", choices=("backup", "filesystem", "sysdiagnose"), default="",
                        help="explicit iPhone input format for --phone; filesystem is an extracted tree, sysdiagnose is a directory or TAR/TAR.GZ")
    parser.add_argument("--extended-windows", action="store_true", help="opt-in additional existing Windows event records; does not elevate or enable logging")


def scope_validate(parser, args):
    # A mistyped phone folder must stop here: scanning nothing and printing an
    # ordinary "no known indicator" report reads like an all-clear.
    # Only a local path is tested: asking Windows whether a network path exists
    # would contact that server. Network paths are refused later, as before.
    if (args.phone and not path_problem(os.path.abspath(args.phone))
            and not os.path.exists(args.phone)):
        parser.error("phone evidence not found: " + args.phone + " - nothing was checked")
    if args.ios_input and not args.phone:
        parser.error("--ios-input requires --phone")
    if args.backup_password and args.ios_input in ("filesystem", "sysdiagnose"):
        parser.error("--backup-password is for backup input only")
    if bool(args.target) != (args.scan_type == "targeted"):
        parser.error("--scan-type targeted requires --target; --target requires --scan-type targeted")
    if args.phone and args.target:
        parser.error("use --phone for a collection, or --target for computer files/profiles")
    if args.quick and args.scan_type == "targeted":
        parser.error("--quick cannot be combined with targeted")
    if args.age_recipient_file and not args.collect_android:
        parser.error("--age-recipient-file requires --collect-android")
    if args.collect_android and (args.phone or args.target or args.preview or args.phone_guide or args.describe):
        parser.error("--collect-android is a separate acquisition command")
    if args.backup_password and not (args.phone or args.collect_android):
        parser.error("--backup-password requires --phone")
    if args.update and (args.target or args.phone or args.preview or args.phone_guide or args.collect_android):
        parser.error("--update is a separate operation")
    for path in args.target:
        problem = path_problem(os.path.abspath(path))
        if problem:
            parser.error("target refused: " + problem)
        if not os.path.exists(path):
            parser.error("target does not exist: " + path)
    if args.target and args.patterns and not args.pattern_path:
        args.pattern_path = list(args.target)


def scope_record(args):
    result = {"scan_type": args.scan_type, "targets": [sanitize_untrusted(os.path.abspath(p)) for p in args.target],
              "phone": bool(args.phone), "scanned": False,
              "ios_input": getattr(args, "ios_input", ""),
              "host_platform": sys.platform,
              "limits": ["Read-only local evidence; no infection-free guarantee.",
                         "File hashing remains bounded to 120 MiB per file.",
                         "Full means broader checks in the usual roots, not every drive or every user."]}
    return result


def scope_preview(args):
    result = scope_record(args)
    if args.phone:
        folder = os.path.abspath(args.phone)
        problem = path_problem(folder)
        if problem:
            raise ValueError("phone folder refused: " + problem)
        if getattr(args, "ios_input", "") in ("filesystem", "sysdiagnose"):
            result["collection_type"] = "ios-" + args.ios_input
            result["checks"] = ["supported local iPhone artifacts", "bounded evidence inventory"]
            result["limits"].append("Preview does not open the archive or validate schemas. No device acquisition is performed.")
            return result
        artifacts = ("packages.json", "processes.txt", "processes.json", "backup.ab", "dumpsys.txt",
                     "getprop.txt", "files.json", "Manifest.plist", "Manifest.db", "Info.plist")
        result["artifacts"] = {}
        for name in artifacts:
            path = os.path.join(folder, name)
            problem = path_problem(path)
            result["artifacts"][name] = "refused" if problem else "present" if os.path.isfile(path) else "missing"
        is_ios = getattr(args, "ios_input", "") == "backup" or result["artifacts"]["Manifest.plist"] == "present"
        result["collection_type"] = "ios-backup" if is_ios else "androidqf" if result["artifacts"]["packages.json"] == "present" else "unrecognized"
        result["checks"] = (["manifest", "supported message text and metadata", "Safari profiles", "optional Chrome and historical Firefox visits", "data-usage process names", "application identifiers", "supported cache, configuration, analytics and diagnostic artifacts"]
                            if is_ios else ["packages", "processes", "settings and properties", "file inventory", "logs and crashes", "SMS backup", "optional decrypted intrusion logs"])
        intrusion = os.path.join(folder, "intrusion_logs")
        problem = path_problem(intrusion)
        result["artifacts"]["intrusion_logs"] = "refused" if problem else "present" if os.path.isdir(intrusion) else "missing"
        result["limits"].append("Presence is not validation: corrupt, unsupported or encrypted artifacts can still be unreadable.")
    elif args.target:
        result["checks"] = ["selected file fingerprints", "supported browser artifacts inside selected profiles", "supported copied Prefetch and Amcache artifacts"]
        result["limits"].append("Live host, live registry and system event checks are outside targeted scope.")
    elif args.scan_type == "browser":
        result["checks"] = ["browser"]
        result["limits"].append("Only browser profiles and desktop apps with a built-in browser are read; "
                                "files, startup entries, DNS, registry and system events are not.")
    else:
        from .context import ScanContext
        from .readers import reader_select
        result["checks"] = [spec.name for spec in reader_select(ScanContext(None, patterns=args.patterns))]
    if not args.phone and sys.platform != "win32":
        result["limits"].append("Linux/macOS host checks cover selected startup configuration only, not Windows DNS, registry or event sources.")
    return result


def scope_guide(platform):
    if platform == "android":
        return ("Android preparation\n"
                "Guided acquisition: --collect-android LOCAL_OUTPUT_FOLDER (separate download and consent step).\n"
                "Or use the official AndroidQF release: https://github.com/mvt-project/androidqf/releases\n"
                "With the device owner's consent, connect by USB, enable USB debugging and approve this computer on the phone.\n"
                "Choose whether to include SMS during collection; confirm the backup on the phone. Acquisition changes device state.\n"
                "Current AndroidQF produces a ZIP archive. Extract it locally and select the folder containing packages.json.\n"
                "An age-encrypted .zip.age archive must first be decrypted with its owner's age identity using age.\n"
                "Keep the archive and extracted private records on protected local storage.\n"
                "Preview: --phone FOLDER --preview\n"
                "Check: --phone FOLDER (add --backup-password for an AES-encrypted backup.ab).\n"
                "Missing artifacts remain gaps. Disable USB debugging afterwards if you do not need it.\n")
    return ("iPhone preparation\n"
            "With the owner's consent, make a local Finder, Apple Devices or iTunes backup.\n"
            "Encrypted local backups preserve more artifacts; keep the password privately.\n"
            "Select the device backup folder containing Manifest.plist, Manifest.db and Info.plist.\n"
            "Preview: --phone FOLDER --preview\n"
            "Check: --phone FOLDER (add --backup-password if encrypted).\n"
            "Already acquired filesystem: --phone ROOT --ios-input filesystem\n"
            "Already acquired diagnostics: --phone PATH --ios-input sysdiagnose (directory or TAR/TAR.GZ).\n"
            "Sources stay unchanged; database replay and decryption use temporary local copies, removed after the run.\n"
            "Only supported backup records are checked; no live phone access or cloud download is performed.\n"
            "See https://support.apple.com/108353 for Apple's local-backup instructions.\n")
