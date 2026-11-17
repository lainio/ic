#!/usr/bin/env python3
"""Run and verify the exact Round 03B section 7 everyday selection."""

import json
import subprocess
import sys


PACKAGE = "github.com/lainio/ic/internal/pw"
TESTS = (
    "TestKnownBeforeAnySignerUse",
    "TestAdHistoryNeverSubstitutesForIndependentKnown",
    "TestAuthorizationDoesNotImplySignerUsability",
    "TestInvitationIssuanceAndTimeBoundary",
    "TestBobAcceptV2IndependentContactCommit",
    "TestBobAcceptV2RejectsSignedBindings",
    "TestBobAcceptV2RejectsUnauthenticatedBytes",
    "TestReceiveAcceptanceV2IndependentContacts",
    "TestReceiveAcceptanceV2DuplicateCannotRestoreDelete",
    "TestFirstUseOrderedLocalObservationsV2",
    "TestFirstUseReceiveStrictDeadlineAndCanonicalBytesV2",
    "TestMessageACKAndInboxEitherSenderV2",
    "TestMessageProjectionVersionIsolationV2",
    "TestMessageSingleRecordRollbackV2",
    "TestDenyAndDeleteAreDistinctLocalOperations",
    "TestMessageClientCancellationAfterDispatch",
)


def json_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError(f"duplicate JSON field: {key}")
        fields[key] = value
    return fields


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def verify(output):
    """Print Go's output and require complete, successful test lifecycles."""
    package_state = None
    tests = {}
    errors = []
    for number, line in enumerate(output.splitlines(), 1):
        try:
            event = json.loads(line, object_pairs_hook=json_fields,
                               parse_constant=invalid_constant)
            if not isinstance(event, dict):
                raise ValueError("expected a JSON event object")
        except ValueError as error:
            print(line)
            errors.append(f"line {number}: {error}")
            continue

        # Keep all diagnostic output, even after an invalid event or failure.
        if isinstance(event.get("Output"), str):
            print(event["Output"], end="")
        try:
            action = event.get("Action")
            name = event.get("Test")
            if event.get("Package") != PACKAGE:
                raise ValueError("unexpected or missing package")
            if "Test" in event and (not isinstance(name, str) or not name):
                raise ValueError("invalid test name")
            if action == "start" and name is None and package_state is None:
                package_state = "run"
                continue
            if package_state != "run":
                raise ValueError("event outside the package start/completion")
            if name is not None:
                family = name.split("/", 1)[0]
                if family not in TESTS:
                    raise ValueError(f"unexpected family: {family}")
                if name != family and tests.get(family) not in ("run", "pause"):
                    raise ValueError(f"descendant outside its family: {name}")
                state = tests.get(name)
                if action == "run" and state is None:
                    tests[name] = "run"
                elif action == "pause" and state == "run":
                    tests[name] = "pause"
                elif action == "cont" and state == "pause":
                    tests[name] = "run"
                elif action in ("pass", "fail", "skip") and state == "run":
                    tests[name] = action
                    if action != "pass":
                        errors.append(f"{name}: {action}")
                elif action != "output" or state not in ("run", "pause"):
                    raise ValueError(f"invalid test transition: {name}: {action}")
            elif action in ("pass", "fail", "skip"):
                package_state = action
            elif action != "output":
                raise ValueError(f"invalid package action: {action}")
            if action == "output" and not isinstance(event.get("Output"), str):
                raise ValueError("output event has no text")
        except ValueError as error:
            errors.append(f"line {number}: {error}")

    if output and not output.endswith("\n"):
        errors.append("incomplete final JSON line")
    if package_state != "pass":
        errors.append(f"package did not complete successfully: {package_state}")
    missing = set(TESTS) - tests.keys()
    if missing:
        errors.append("missing families: " + ", ".join(sorted(missing)))
    unfinished = [name for name, state in tests.items() if state != "pass"]
    if unfinished:
        errors.append("tests without a pass: " + ", ".join(unfinished))
    for error in errors:
        print(f"test_fast: {error}", file=sys.stderr)
    return not errors, len(tests) - len(TESTS)


def main():
    # Restrict arguments so -run/-skip/-short/-args cannot narrow the contract
    # or change test scheduling. Other Makefile test targets remain unrestricted.
    if len(sys.argv) < 2 or sys.argv[2:] not in ([], ["-count=1"]):
        print("test_fast: TEST_ARGS must be empty or -count=1", file=sys.stderr)
        return 2

    # Go applies this single anchored component to top-level names only;
    # with no slash component, every descendant remains eligible.
    pattern = "^(" + "|".join(TESTS) + ")$"
    command = [sys.argv[1], "test", *sys.argv[2:], "-json", "-timeout=10m",
               "./internal/pw", "-run", pattern]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE)
    except OSError as error:
        print(f"test_fast: cannot launch Go: {error}", file=sys.stderr)
        return 127

    try:
        output = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        print(result.stdout.decode("utf-8", errors="replace"), end="")
        print("test_fast: invalid UTF-8 result stream", file=sys.stderr)
        valid = False
    else:
        valid, descendants = verify(output)
    # Go's nonzero status wins over verification failures. Make itself maps
    # recipe failures to exit 2, while printing the recipe's original status.
    if result.returncode:
        return (result.returncode if result.returncode > 0
                else 128 - result.returncode)
    if not valid:
        return 1
    print(f"test_fast: {len(TESTS)} families and {descendants} descendants passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
