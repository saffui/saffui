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

# The most read of a member of an export: five times the largest log of a
# module in a pass of the nine plans, 206 KiB. A member is read up to
# one byte past this, whatever its header says, and parsed once the
# document before it is gone: this bounds what is read of one member, and
# so what its parse holds in memory. The suite stores or deflates them,
# and no other method is read.
MOST_MEMBER_BYTES = 1024 * 1024
KNOWN_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
# The most an export may weigh on disk to be opened: about ten times the
# largest of a pass of the nine plans, 1.5 MB. A heavier one is unreadable.
MOST_EXPORT_BYTES = 16 * 1024 * 1024

# What the summary says is bounded too, whatever the exports hold: each name
# cut to a few hundred characters, a few dozen conditions for a module, and
# the whole to 1 MiB, where a pass of the nine plans writes about 83 KB.
MOST_NAME_CHARACTERS = 200
MOST_CONDITIONS_SAID = 50
MOST_SUMMARY_BYTES = 1024 * 1024


def cut(name):
    name = str(name)
    return name if len(name) <= MOST_NAME_CHARACTERS else name[:MOST_NAME_CHARACTERS] + "..."


def measure(lines):
    return sum(len(line.encode()) + 1 for line in lines)


def read_arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exports", required=True)
    parser.add_argument("--plans", required=True)
    parser.add_argument("--expected-skips", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--within", type=int, default=0, help="seconds it may take, then it ends")
    return parser.parse_args()


def open_export(export):
    """The export as a file, when it is a plain file within the bound: one
    opened as a pipe or a device could wait for ever."""
    if not is_plain_and_small(os.lstat(export)):
        raise OSError("not a plain file within the bound")
    descriptor = os.open(export, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    if not is_plain_and_small(os.fstat(descriptor)):
        os.close(descriptor)
        raise OSError("not a plain file within the bound")
    return os.fdopen(descriptor, "rb")


def is_plain_and_small(status):
    return stat.S_ISREG(status.st_mode) and status.st_size <= MOST_EXPORT_BYTES


def read_modules(export):
    """Each module of one export: its information, the seconds from its
    first entry to its last, its failed or warned conditions as (block,
    condition, result), the first few dozen of them, and how many more."""
    with open_export(export) as file, zipfile.ZipFile(file) as archive:
        for member in sorted(archive.infolist(), key=lambda member: member.filename):
            if not member.filename.endswith(".json"):
                continue
            if member.compress_type not in KNOWN_METHODS:
                raise ValueError("a member of another method")
            with archive.open(member) as stream:
                content = stream.read(MOST_MEMBER_BYTES + 1)
            if len(content) > MOST_MEMBER_BYTES:
                raise ValueError("a member past the bound")
            document = json.loads(content)
            del content
            known = document["testInfo"]
            info = {key: known[key] for key in ("testName", "variant", "status", "result") if key in known}
            results = document.get("results", [])
            blocks = {}
            conditions = []
            more = 0
            times = [entry.get("time") for entry in results]
            times = [time for time in times if isinstance(time, (int, float))]
            seconds = (times[-1] - times[0]) / 1000 if times else 0.0
            for entry in results:
                if entry.get("startBlock"):
                    blocks[entry.get("blockId")] = cut(entry.get("msg", ""))
                    continue
                if entry.get("result") in ("FAILURE", "WARNING"):
                    if len(conditions) < MOST_CONDITIONS_SAID:
                        block = blocks.get(entry.get("blockId"), "")
                        conditions.append((block, cut(entry.get("src", "?")), cut(entry["result"])))
                    else:
                        more += 1
            del document, known, results, blocks, times
            yield info, seconds, conditions, more


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
    if not isinstance(variant, dict):
        return ""
    return cut("".join("[{}={}]".format(cut(key), cut(variant[key])) for key in sorted(variant)))


def summarize_export(export, plans, skips, room):
    """The lines of one export, read whole before any is kept, unless what
    it notes alone fills the room, and whether the room left in the summary
    cut them short. Cut short, they say first each module FAILED where a
    skip is expected, then what room is left."""
    configuration = find_configuration(export, plans)
    header = "{} ({})".format(cut(os.path.basename(export)), configuration)
    counts = {}
    kept, noted = [], []
    used_kept, used_noted = 0, measure([header])
    full = False
    for info, seconds, conditions, more in read_modules(export):
        result = cut(info.get("result") or "UNKNOWN")
        # The runner takes a module it expects skipped as skipped when it fails.
        if result == "FAILED" and any(is_expected_skip(skip, info, configuration) for skip in skips):
            line = "  FAILED where a skip is expected: " + cut(info.get("testName", "?"))
            used_noted += measure([line])
            if used_noted > room:
                return [header] + noted, True
            noted.append(line)
        if full:
            continue
        said = [
            "  {}{} {} {} {:.1f} s".format(
                cut(info.get("testName", "?")),
                write_variant(info.get("variant")),
                cut(info.get("status", "?")),
                result,
                seconds,
            )
        ]
        for block, condition, outcome in conditions:
            said.append("    {} {} in '{}'".format(outcome, condition, block))
        if more:
            said.append("    and {} more".format(more))
        if used_noted + used_kept + measure(said) > room:
            full = True
            continue
        counts[result] = counts.get(result, 0) + 1
        kept.extend(said)
        used_kept += measure(said)
    if not full:
        counted = "  modules {}: {}".format(
            sum(counts.values()),
            ", ".join("{} {}".format(count, result) for result, count in sorted(counts.items())),
        )
        if used_noted + used_kept + measure([counted]) <= room:
            return [header] + kept + [counted] + noted, False
    while kept and used_noted + used_kept > room:
        used_kept -= measure([kept.pop()])
    return [header] + noted + kept, True


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
    size = 0
    for export in sorted(glob.glob(os.path.join(arguments.exports, "*.zip"))):
        try:
            said, full = summarize_export(export, plans, skips, MOST_SUMMARY_BYTES - size)
        # A cut or forged archive raises anything: it is one export lost.
        except Exception:
            said, full = ["{} unreadable".format(cut(os.path.basename(export)))], False
        if size + measure(said) > MOST_SUMMARY_BYTES:
            said, full = [], True
        lines.extend(said)
        size += measure(said)
        if full:
            lines.append("The summary stops here, at 1 MiB: the exports say the rest.")
            break
    # Written aside, then put in place: the summary is there whole or not at all.
    part = arguments.out + ".part"
    descriptor = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as file:
        file.write("\n".join(lines) + "\n")
    os.replace(part, arguments.out)


if __name__ == "__main__":
    main()
