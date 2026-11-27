"""Summarizes the exports of a run: for each module of each plan, its
variant, its result, how long it ran, and the name of each condition that
failed or warned, with the block it was checked in. It also names each
module the list of skips expects that ended FAILED, which the runner lets
pass as skipped. An export that is no plain file, or that fails to be
read in any way, is named unreadable, and the others are summarized.

Standard library only, run isolated (python3 -I). It writes no message of a
condition and nothing of the configuration: both may hold a secret.
"""

import argparse
import fnmatch
import glob
import json
import os
import signal
import stat
import zipfile

# The most a member of an export may hold once read: the largest log of a
# module in a pass of the nine plans is 206 KiB. A member is read up to one
# byte past this, whatever its header says, so that no more of one is
# read; the suite stores or deflates them, and no other method is read.
MOST_MEMBER_BYTES = 16 * 1024 * 1024
KNOWN_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


def read_arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exports", required=True)
    parser.add_argument("--plans", required=True)
    parser.add_argument("--expected-skips", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--within", type=int, default=0, help="seconds it may take, then it ends")
    return parser.parse_args()


def open_export(export):
    """The export as a file, when it is a plain file: one opened as a pipe
    or a device could wait for ever."""
    if not stat.S_ISREG(os.lstat(export).st_mode):
        raise OSError("not a plain file")
    descriptor = os.open(export, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OSError("not a plain file")
    return os.fdopen(descriptor, "rb")


def read_modules(export):
    """Each module of one export: its information, the seconds from its
    first entry to its last, and its failed or warned conditions as (block,
    condition, result)."""
    with open_export(export) as file, zipfile.ZipFile(file) as archive:
        for member in sorted(archive.infolist(), key=lambda member: member.filename):
            if not member.filename.endswith(".json"):
                continue
            if member.compress_type not in KNOWN_METHODS:
                raise ValueError("a member of another method")
            with archive.open(member) as file:
                content = file.read(MOST_MEMBER_BYTES + 1)
            if len(content) > MOST_MEMBER_BYTES:
                raise ValueError("a member past the bound")
            document = json.loads(content)
            info = document["testInfo"]
            blocks = {}
            conditions = []
            times = [entry.get("time") for entry in document.get("results", [])]
            times = [time for time in times if isinstance(time, (int, float))]
            seconds = (times[-1] - times[0]) / 1000 if times else 0.0
            for entry in document.get("results", []):
                if entry.get("startBlock"):
                    blocks[entry.get("blockId")] = entry.get("msg", "")
                    continue
                if entry.get("result") in ("FAILURE", "WARNING"):
                    block = blocks.get(entry.get("blockId"), "")
                    conditions.append((block, entry.get("src", "?"), entry["result"]))
            yield info, seconds, conditions


def read_plans(path):
    """Each plan of plans.txt, by its name, and the configuration it runs with."""
    plans = {}
    with open(path) as file:
        for line in file:
            words = line.split()
            if len(words) == 2 and not words[0].startswith("#"):
                plans[words[0].split("[")[0]] = words[1]
    return plans


def find_configuration(export, plans):
    """The configuration an export was made with, as the runner was given it:
    an export is named after its plan, then its variants."""
    named = [plan for plan in plans if os.path.basename(export).startswith(plan + "-")]
    return "configs/" + plans[max(named, key=len)] if named else ""


def is_expected_skip(skip, info, configuration):
    if not fnmatch.fnmatch(info.get("testName", ""), skip["test-name"]):
        return False
    if not fnmatch.fnmatch(configuration, skip["configuration-filename"]):
        return False
    variant = skip.get("variant", "*")
    if variant == "*":
        return True
    known = info.get("variant") or {}
    return all(known.get(key) == value for key, value in variant.items())


def write_variant(variant):
    return "".join("[{}={}]".format(key, variant[key]) for key in sorted(variant or {}))


def summarize_export(export, plans, skips):
    """The lines of one export, read whole before any is kept."""
    configuration = find_configuration(export, plans)
    counts = {}
    skipped_and_failed = []
    lines = ["{} ({})".format(os.path.basename(export), configuration)]
    for info, seconds, conditions in read_modules(export):
        result = info.get("result") or "UNKNOWN"
        counts[result] = counts.get(result, 0) + 1
        lines.append(
            "  {}{} {} {} {:.1f} s".format(
                info.get("testName", "?"),
                write_variant(info.get("variant")),
                info.get("status", "?"),
                result,
                seconds,
            )
        )
        for block, condition, outcome in conditions:
            lines.append("    {} {} in '{}'".format(outcome, condition, block))
        # The runner takes a module it expects skipped as skipped when it fails.
        if result == "FAILED" and any(is_expected_skip(skip, info, configuration) for skip in skips):
            skipped_and_failed.append(info.get("testName", "?"))
    lines.append(
        "  modules {}: {}".format(
            sum(counts.values()),
            ", ".join("{} {}".format(count, result) for result, count in sorted(counts.items())),
        )
    )
    for name in skipped_and_failed:
        lines.append("  FAILED where a skip is expected: " + name)
    return lines


def main():
    arguments = read_arguments()
    # Past its time, the process ends on the alarm, and writes nothing, even
    # when its caller ignores the alarm.
    if arguments.within:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(arguments.within)
    with open(arguments.expected_skips) as file:
        skips = json.load(file)
    plans = read_plans(arguments.plans)
    lines = []
    for export in sorted(glob.glob(os.path.join(arguments.exports, "*.zip"))):
        try:
            lines.extend(summarize_export(export, plans, skips))
        # A cut or forged archive raises anything: it is one export lost.
        except Exception:
            lines.append("{} unreadable".format(os.path.basename(export)))
    descriptor = os.open(arguments.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as file:
        file.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
