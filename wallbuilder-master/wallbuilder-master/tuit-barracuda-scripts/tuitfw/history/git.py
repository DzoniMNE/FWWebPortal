import os.path
from shutil import rmtree
import subprocess
from tempfile import mkdtemp
from typing import Any, Iterable, Mapping
from ..common import NetworkObjectEntry, output_entries
from .. import loggage


def _do_remember(repo_path: str,
                 hist_file_name: str,
                 entries: Mapping[str, Iterable[NetworkObjectEntry]],
                 message: str,
                 push: bool) -> None:
    logger = loggage.get_logger(__name__)

    # write out the entries
    hist_full_name = os.path.join(repo_path, hist_file_name)
    with open(hist_full_name, "w") as hist_file:
        output_entries(entries, hist_file)

    # check for changes
    # git -C $DIR diff --quiet $FILE
    result = subprocess.run(
        [
            "git",
            "-C", repo_path,
            "diff",
            "--quiet",
            hist_file_name,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode == 0:
        # no changes; nothing to commit
        logger.debug("no changes to rule list; not committing")
        return
    elif result.returncode != 1:
        logger.error(f"error checking for changes: git exited with code {result.returncode}")
        logger.error(f"git stdout: {result.stdout}")
        logger.error(f"git stderr: {result.stderr}")
        return

    logger.debug("rules changed; committing")

    # commit
    # git -C $DIR commit -m $MESSAGE $FILE
    result = subprocess.run(
        [
            "git",
            "-C", repo_path,
            "commit",
            "-m", message,
            hist_file_name,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode != 0:
        logger.error(f"error committing history entry: git exited with code {result.returncode}")
        logger.error(f"git stdout: {result.stdout}")
        logger.error(f"git stderr: {result.stderr}")
        return

    logger.debug("pushing")

    if push:
        result = subprocess.run(
            [
                "git",
                "-C", repo_path,
                "push",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if result.returncode != 0:
            logger.warning(f"error pushing history: git exited with code {result.returncode}")
            logger.warning(f"git stdout: {result.stdout}")
            logger.warning(f"git stderr: {result.stderr}")
            return


def remember(entries: Mapping[str, Iterable[NetworkObjectEntry]],
             history_config: Mapping[str, Any],
             message: str) -> None:
    logger = loggage.get_logger(__name__)

    repo_path = history_config['repo']
    hist_file_name = history_config['file_name']

    fresh_checkout = history_config.get('fresh_checkout', False)
    push = history_config.get('push', True)

    if fresh_checkout:
        # fresh checkout mode; adapt paths
        tmpdir = mkdtemp()
        try:
            repo_uri = repo_path
            repo_path = os.path.join(tmpdir, "repo")

            # clone the repo
            # git clone --depth=1 $REPO $DIR
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    repo_uri,
                    repo_path,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            if result.returncode != 0:
                logger.error(f"error cloning history repository: git exited with code {result.returncode}")
                logger.error(f"git stdout: {result.stdout}")
                logger.error(f"git stderr: {result.stderr}")
                return

            _do_remember(repo_path, hist_file_name, entries, message, push)

        finally:
            # cleanup
            rmtree(tmpdir)

    else:
        _do_remember(repo_path, hist_file_name, entries, message, push)
