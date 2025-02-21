#!/usr/bin/env python3

"""
This script automates the rote work to prepare for a release, as specified in RELEASE.md:

  1) Checks that "Slow Tests" and "Build and Test" (CI) have succeeded on the current commit.
  2) Creates a new annotated tag for the current commit, based on the release version found in RELEASE_NOTES.md.
  3) Attempts to parse the Java code size from the GitHub Actions logs and appends that value (along with the version)
     to java/code_size.json.
  4) Resets RELEASE_NOTES.md to the next presumed version (e.g., incrementing PATCH).
  5) Updates the version throughout the repository to that new version.
  6) Commits these changes in a single "Reset for version X" commit.

Usage:
  1) Ensure you are on the commit you wish to mark as a release
      and that both Build and Test and Slow Tests have passed on that commit.
  2) Run this script: ./prepare_release.py
  3) Push the tag, the tag's commit, and the version reset/update commit to the proper remotes.

  Optional arguments:
    --skip-main-branch-check     Skip the check that ensures we are on 'main' branch.
    --skip-ci-tests-pass-check   Skip the check that continous integration tests have passed on this commit.
    --skip-worktree-clean-check  Skip the check that the working tree is clean before running this script. Not recommended.
"""

import os
import sys
import subprocess
import json
import re
from pathlib import Path
from shutil import which
import time
import argparse


class ReleaseFailedException(Exception):
    pass


# Before we make any changes to the working tree/repository state, we add the command to rollback that change
#  to this list. If we encounter an error, we execute these commands in order to return the repository to its
#  original state.
# Each of these commands should be independent of each other, as if one of them fails, we will still try to
#  execute the rest while performing a rollback.
on_failure_rollback_commands: list[list[str]] = []


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automates the release preparation workflow."
    )

    parser.add_argument(
        "--skip-main-branch-check",
        action="store_true",
        help="Skip the check to ensure the current branch is 'main'."
    )
    parser.add_argument(
        "--skip-ci-tests-pass-check",
        action="store_true",
        help="Skip the check that continous integration tests have passed on this commit."
    )
    parser.add_argument(
        "--skip-worktree-clean-check",
        action="store_true",
        help="Skip the check that the working tree is clean before running this script. Not recommended."
    )

    args = parser.parse_args()

    try:
        prepare_release(skip_main_check=args.skip_main_branch_check, skip_tests_pass_check=args.skip_ci_tests_pass_check, skip_worktree_clean_check=args.skip_worktree_clean_check)
        exit_code = 0
    except subprocess.CalledProcessError as e:
        print(f"Error: command {e.cmd} exited with status {e.returncode}.")
        exit_code = e.returncode
    except ReleaseFailedException:
        # We printed out the user friendly error before we threw the exception.
        exit_code = 1
    except KeyboardInterrupt:
        print("User interrupted execution! Aborting...")
        exit_code = 1
    except Exception as ex:
        print(f"Unexpected error: {ex}")
        exit_code = 1

    if exit_code != 0:
        for rollback_command in on_failure_rollback_commands:
            try:
                run_command(rollback_command)
            except subprocess.CalledProcessError:
                rollback_command_str = " ".join(rollback_command)
                print(f"Unable to execute `{rollback_command_str}` after failure, working tree or repository may still be in dirty state.")

    sys.exit(exit_code)


def prepare_release(skip_main_check: bool = False, skip_tests_pass_check: bool = False, skip_worktree_clean_check: bool = False) -> None:
    setup_and_check_env(skip_main_check, skip_worktree_clean_check)
    REPO_NAME = get_repo_name()
    RELEASE_NOTES_FILE_PATH = Path("RELEASE_NOTES.md")

    # Get the commit sha of the commit we intend to mark as the release.
    head_sha = run_command(["git", "rev-parse", "HEAD"]).strip()
    short_sha = head_sha[:9]
    print(f"Searching for GitHub Actions runs for commit {short_sha}...")

    # Release Step 1: Ensure that CI tests pass!
    #   - Check GitHub to see if the latest commit has all tests passing, including the nightly "Slow Tests".
    #   - If not, fix the tests before releasing!
    # If needed, you can run the Slow Tests manually under the repository Actions tab on GitHub.
    # You should run the Slow Tests before running this script.
    if not skip_tests_pass_check:
        build_and_test_run_id = check_workflow_success(REPO_NAME, "Build and Test", head_sha)
        slow_test_run_id = check_workflow_success(REPO_NAME, "Slow Tests", head_sha)

        print("Found GitHub Actions runs! They look good, but please double check manually as well.")
        print(f"Build and Test: https://github.com/signalapp/{REPO_NAME}/actions/runs/{build_and_test_run_id}")
        print(f"Slow Tests:     https://github.com/signalapp/{REPO_NAME}/actions/runs/{slow_test_run_id}")
    else:
        print("Skipping checking that tests pass!")
        print("Be sure to manually check for passing test runs at:")
        print(f"  https://github.com/signalapp/{REPO_NAME}/actions/workflows/build_and_test.yml")
        print(f"  https://github.com/signalapp/{REPO_NAME}/actions/workflows/slow_tests.yml")

    # Release Step 2: Tag the release commit.
    #   - Look up the next version number vX.Y.Z according to our semantic versioning scheme, which
    #       is manually adjusted as needed in RELEASE_NOTES.md
    #   - Tag the release commit with an annotated tag titled with that version number and a message
    #       containing the release notes summarizing the notable changes since the last release from
    #       RELEASE_NOTES.md
    #   - Prompt the user to give the Release Notes a final human review. The expected format of the
    #        release notes is specified in RELEASE.md
    head_release_version = tag_new_release(RELEASE_NOTES_FILE_PATH)

    # Release Step 3: Prepare the repository for the next version
    #
    # Step 3, Stage 1: Update the version number throughout the repository to match the next presumed version
    #
    #  We already have a script that does most of this, update_versions.py. We run it and pass the presumed next version
    #  number as an argument.
    #
    #  We also run cargo check to make sure the version number in Cargo.lock is updated.

    #  We always start a release by presuming the next release will not be a breaking one. So, if the last release was v0.x.y, the next release
    #  is always presumed to be v0.x.(y+1) until a breaking change is merged.
    major, minor, patch = parse_version(head_release_version)
    next_patch = patch + 1
    presumptive_next_version = f"v{major}.{minor}.{next_patch}"

    if not skip_worktree_clean_check:
        # Check again that the worktree is clean, just to be doubly sure we don't lose data.
        run_command(["git", "diff-index", "--quiet", "HEAD", "--"])
        on_failure_rollback_commands.append(["git", "reset", "--hard"])

    run_command(["./bin/update_versions.py", presumptive_next_version])
    # Use subprocess.run() directly here to pass through `cargo check` output, because it may take a while.
    subprocess.run(["cargo", "check", "--workspace", "--all-features"], check=True)

    # Step 3, Stage 2: Record the code size of the just cut release in code_size.json
    #   Get the cannonical computed code size for the Java library on the commit for the tagged release from GitHub
    #   Actions, and then add it to a new entry in java/code_size.json.
    #
    #   The version for the new entry is the same as the version for the release that was just tagged, i.e. v0.x.y, not v0.x.(y+1).

    # The "Build and Test" log contains the output of the 'java/check_code_size.py', which records the code size.
    # So, we try to find the "Build and Test" log for this commit, but one may not exist.
    # If it doesn't exist, we prompt the user to look it up manually.
    if not skip_tests_pass_check:
        print(f"Extracting Java library size from GitHub Actions run (ID: {build_and_test_run_id})...")
        build_and_test_log = run_command(["gh", "run", "view", str(build_and_test_run_id), "--log"])
    else:
        build_and_test_log = ""

    pattern = r"update code_size\.json with (\d+)"  # Matches output of print_size_for_release in check_code_size.py
    match = re.search(pattern, build_and_test_log)
    if match:
        java_code_size_int = int(match.group(1))
    else:
        print("Could not get logs to find Java code size automatically.")
        print("This might be due to a known gh cli bug: https://github.com/cli/cli/issues/5011")
        print(f"You'll have to find it manually in the list of runs: https://github.com/signalapp/{REPO_NAME}/actions/workflows/build_and_test.yml")
        input_str = input("Please lookup the code size manually and enter it: ")
        java_code_size_int = int(input_str)

    code_size_file = Path("java/code_size.json")
    append_code_size(code_size_file, head_release_version, java_code_size_int)

    # Step 3, Stage 3: Clear RELEASE_NOTES.md, and update it with the presumptive next version number
    #
    #  As we work, we keep updated running release notes for *just* the next release in RELEASE_NOTES.md. Because we just made a release that
    #  included all the changes previously in RELEASE_NOTES.md, it's now time to reset RELEASE_NOTES.md
    #
    #  Thus, we edit RELEASE_NOTES.md so that it just contains the next version number on its own line, followed by one newline.
    with RELEASE_NOTES_FILE_PATH.open("w", encoding="utf-8") as f:
        f.write(presumptive_next_version + "\n\n")

    # Step 3, Stage 4: Commit all changes in a single commit!
    new_release_version = get_first_line_of_file(RELEASE_NOTES_FILE_PATH)
    run_command([
        "git", "commit", "-am", f"Reset for version {new_release_version}"
    ])

    print("\nRelease process complete!")
    print("Next steps:")
    print("1) Verify the GitHub Actions runs above passed.")
    print("2) If they passed, push to the proper remote(s), e.g.:")
    print(f"     git push <remote> HEAD~1:main {head_release_version} && git push <working-remote> HEAD:main {head_release_version}")
    print("3) To review the reset commit, you can run:")
    print("     git show")


def setup_and_check_env(skip_main_check: bool = False, skip_worktree_clean_check: bool = False) -> None:
    """
    Checks release environment pre-conditions.
    Throws on failure.
    """
    # We change into the repo root dir so we can use root-relative paths throughout
    #   the script. This matches the convention in other scripts, like update_versions.py.
    repo_dir_path = run_command(["git", "rev-parse", "--show-toplevel"])
    os.chdir(repo_dir_path)

    # We need to be authenticated with GitHub to fetch Actions run results from
    #   the API. We use these results to check that tests are passing, and to fetch
    #   the Java library code size from the Java test run logs.
    # We opt to check this up front now and fail early, to try to minimize failures
    #   part way through the script that may leave the repository in a weird state.
    check_gh_installed_and_authed()

    # Optionally, we check to make sure we are on main as a convenience.
    # Some people prefer instead to make this commit on a different branch, and
    #  then to 'git push <origin> HEAD:main', so we accomodate that with an opt-out.
    if not skip_main_check:
        current_branch = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"]).strip()
        if current_branch != "main":
            print(f"Error: You are on branch '{current_branch}'.")
            print("Please switch to 'main' or add the '--skip-main-branch-check' flag and then try again.")
            raise ReleaseFailedException

    if not skip_worktree_clean_check:
        try:
            run_command(["git", "diff-index", "--quiet", "HEAD", "--"])
        except subprocess.CalledProcessError:
            print("Error: Git working tree is not clean! This can cause unexpected behavior, as this script commits to Git.")
            print("Please stash or commit your changes.")
            print("You can also pass `--skip-worktree-clean-check` and try again to bypass this check, but this will result in")
            print("any changes in your worktree being comitted to Git as part of the release, and is thus not recommended.")
            raise ReleaseFailedException

    if not skip_worktree_clean_check:
        try:
            run_command(["git", "diff-index", "--quiet", "HEAD", "--"])
        except subprocess.CalledProcessError:
            print("Error: Git working tree is not clean! This can cause unexpected behavior, as this script commits to Git.")
            print("Please stash or commit your changes.")
            print("You can also pass `--skip-worktree-clean-check` and try again to bypass this check, but this will result in")
            print("any changes in your worktree being comitted to Git as part of the release, and is thus not recommended.")
            sys.exit(1)


def tag_new_release(release_notes_file_path: Path) -> str:
    if not release_notes_file_path.is_file():
        print(f"Error: {release_notes_file_path} not found. Cannot proceed with release.")
        raise ReleaseFailedException

    # Read the top line of RELEASE_NOTES.md for the release version
    head_release_version = get_first_line_of_file(release_notes_file_path)

    print("Opening an editor to create an annotated tag for this release.")
    print("Please review and edit the release notes as needed.")
    print("Once they look good, save and exit the editor to finalize the tag.\n")
    time.sleep(5)

    # Tag the release (and open an editor for the user)
    # NB: We call subprocess.run() directly rather than run_command so we don't redirect stdin/stdout.
    subprocess.run(
        ["git", "tag", "--annotate", "--force", "--edit", head_release_version, "-F", str(release_notes_file_path)],
        check=True
    )
    on_failure_rollback_commands.append(["git", "tag", "-d", head_release_version])
    print(f"Tagged new release: {head_release_version}")
    return head_release_version


def get_repo_name() -> str:
    # Some devs store the repo as "origin" remote, others store it as "private"
    for remote in ("private", "origin"):
        try:
            remote_url = run_command(["git", "remote", "get-url", remote], print_error=False).strip()
        except subprocess.CalledProcessError:
            continue
        else:
            break
    else:
        raise RuntimeError("Could not find a valid remote (origin or private).")

    repo = remote_url.rsplit("/", 1)[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return repo


def check_gh_installed_and_authed() -> None:
    """
    Checks that the GitHub CLI ('gh') is installed and the user is authenticated.
    Throws ReleaseFailedException if gh is not installed or authenticated.
    """
    if which("gh") is None:
        print("Error: GitHub CLI (gh) is not installed. Please install it and re-run.")
        raise ReleaseFailedException

    auth_status = subprocess.run(
        ["gh", "auth", "status"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if auth_status.returncode != 0:
        print("You are not logged into GitHub CLI. Please run 'gh auth login' and re-run this script.")
        raise ReleaseFailedException


def run_command(cmd: list[str], print_error: bool = True) -> str:
    """
    Runs a shell command and returns its stdout as a string.
    If check=True, raises a CalledProcessError for non-zero exit codes.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if print_error:
            print(f"Error while running command: {cmd}")
            if e.stdout:
                print("STDOUT:", e.stdout)
            if e.stderr:
                print("STDERR:", e.stderr)
        raise


def check_workflow_success(repo_name: str, workflow_name: str, head_sha: str) -> int:
    """
    Checks if a GitHub Actions workflow (workflow_name) has a run on HEAD (head_sha)
    that completed successfully. Returns the run ID if found and successful;
    otherwise prints an error and throws an exception.
    """
    run_search_limit = "100"
    list_cmd = [
        "gh", "run", "list",
        "--workflow", workflow_name,
        "--limit", run_search_limit,
        "--json", "databaseId,headSha,status,conclusion"
    ]

    raw_json = run_command(list_cmd)
    runs_data = json.loads(raw_json)

    matching_runs = [rd for rd in runs_data if rd["headSha"] == head_sha]
    if not matching_runs:
        print(f"Error: Could not find a matching '{workflow_name}' run for commit {head_sha}.")
        print("Make sure CI has run successfully on the current commit before releasing.")
        if workflow_name == "Slow Tets":
            print("Note that Slow Tests do not run automatically.")
            print(f"You must kick them off automatically at: https://github.com/signalapp/{repo_name}/actions/workflows/slow_tests.yml")
        print("If tests have actually passed, you can skip this check by re-running with --skip-ci-tests-pass-check")
        raise ReleaseFailedException

    # Sort by run ID and pick the lowest
    # NB: I opted to pick the lowest one, because as the first, it is less likely to be a re-run.
    matching_runs.sort(key=lambda x: x["databaseId"])
    selected_run_id = int(matching_runs[0]["databaseId"])

    run_view_cmd = [
        "gh", "run", "view", str(selected_run_id),
        "--json", "status,conclusion"
    ]
    run_view_json = run_command(run_view_cmd)
    try:
        view_data = json.loads(run_view_json)
    except json.JSONDecodeError:
        print(f"Error: Could not parse JSON for run {selected_run_id}.")
        raise ReleaseFailedException

    status = view_data.get("status")
    conclusion = view_data.get("conclusion")
    if status != "completed" or conclusion != "success":
        print(f"Error: '{workflow_name}' did not succeed (status={status}, conclusion={conclusion}).")
        print("Please ensure all CI checks have passed before releasing.")
        raise ReleaseFailedException

    return selected_run_id


def parse_version(version_str: str) -> tuple[int, int, int]:
    """
    Given a string in the form 'vMAJOR.MINOR.PATCH',
    returns (MAJOR, MINOR, PATCH) as integers.
    """
    match = re.match(r"^v(\d+)\.(\d+)\.(\d+)$", version_str.strip())
    if not match:
        print(f"Error: version string '{version_str}' is not in 'vMAJOR.MINOR.PATCH' format.")
        raise ValueError
    major, minor, patch = match.groups()
    assert int(major) == 0, "Major version should always be zero, because we never promise stability to external users"
    return int(major), int(minor), int(patch)


def get_first_line_of_file(filepath: Path) -> str:
    """
    Returns the first line of the given file (stripped).
    Throws on failure
    """
    if not filepath.is_file():
        print(f"Error: {filepath} not found.")
        raise FileNotFoundError
    with filepath.open("r", encoding="utf-8") as f:
        return f.readline().strip()


def append_code_size(code_size_file: Path, version: str, code_size: int) -> None:
    """
    Appends an object of the form { "version": <version>, "size": <code_size> }
    to an existing JSON array in code_size_file.
    Throws an exception if file not found or unable to load JSON.
    """
    with code_size_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    data.append({"version": version, "size": code_size})

    with code_size_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()
