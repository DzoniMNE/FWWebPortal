"""
# tuitfw.loggage

Centralized logging functionality. Currently adds a few creature comforts to Python's `logging`
module.

Named `loggage` so as to be obviously different from Python's `logging` module.
"""

import argparse
import logging
import sys
import traceback
from typing import Callable


_ARGPARSE_VERBOSE_MAP = [logging.WARNING, logging.INFO, logging.DEBUG]
_ARGPARSE_QUIET_MAP = [logging.WARNING, logging.ERROR, logging.CRITICAL, logging.CRITICAL + 10]


class LogWrapper:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log(self, level: int, msg, *args, **kwargs) -> None:
        self.logger.log(level, msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs) -> None:
        self.log(logging.DEBUG, msg, *args, **kwargs)
    def info(self, msg, *args, **kwargs) -> None:
        self.log(logging.INFO, msg, *args, **kwargs)
    def warning(self, msg, *args, **kwargs) -> None:
        self.log(logging.WARNING, msg, *args, **kwargs)
    def error(self, msg, *args, **kwargs) -> None:
        self.log(logging.ERROR, msg, *args, **kwargs)
    def critical(self, msg, *args, **kwargs) -> None:
        self.log(logging.CRITICAL, msg, *args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs) -> None:
        self.log(logging.ERROR, msg, *args, exc_info=exc_info, **kwargs)

    def log_lambda(self, level: int, msg_lambda: Callable[[], str], *args, **kwargs) -> None:
        if self.is_enabled_for(level):
            msg = msg_lambda()
            self.log(level, msg, *args, **kwargs)

    def log_traceback(self, level: int = logging.DEBUG) -> None:
        if not self.logger.isEnabledFor(level):
            return

        # take stackframe, dropping the last entry (that's us)
        caller_stack = traceback.extract_stack()
        del caller_stack[-1]

        trace_string = traceback.format_list(caller_stack)
        self.log(level, trace_string)

    def is_enabled_for(self, requested_level: int) -> bool:
        return self.logger.isEnabledFor(requested_level)

    @property
    def debug_enabled(self) -> bool:
        return self.is_enabled_for(logging.DEBUG)
    @property
    def info_enabled(self) -> bool:
        return self.is_enabled_for(logging.INFO)
    @property
    def warning_enabled(self) -> bool:
        return self.is_enabled_for(logging.WARNING)
    @property
    def error_enabled(self) -> bool:
        return self.is_enabled_for(logging.ERROR)
    @property
    def critical_enabled(self) -> bool:
        return self.is_enabled_for(logging.CRITICAL)


class UnboundedMemoryHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def get_logger(module_name: str) -> LogWrapper:
    return LogWrapper(logging.getLogger(module_name))


def add_argparse_options(parser: argparse.ArgumentParser) -> None:
    log_level_group = parser.add_mutually_exclusive_group()
    log_level_group.add_argument(
        '-v', '--verbose', dest='verbose', action='count', default=0,
        help=
            'Increases the logging verbosity from WARNING to INFO (if specified once) or DEBUG (if '
            'specified twice).'
    )
    log_level_group.add_argument(
        '-q', '--quiet', dest='quiet', action='count', default=0,
        help=
            'Reduces the logging verbosity from WARNING to ERROR (if specified once), CRITICAL (if '
            'specified twice), or deactivates logging completely (if specified three times).'
    )


def configure_from_argparse(args: argparse.Namespace) -> None:
    verbose_level, quiet_level = args.verbose, args.quiet

    if verbose_level > 0:
        if verbose_level >= len(_ARGPARSE_VERBOSE_MAP):
            raise ValueError(
                f"maximum {len(_ARGPARSE_VERBOSE_MAP)-1} total specifications of -v and --verbose "
                f"allowed"
            )

        level = _ARGPARSE_VERBOSE_MAP[verbose_level]

    elif quiet_level > 0:
        if quiet_level >= len(_ARGPARSE_QUIET_MAP):
            raise ValueError(
                f"maximum {len(_ARGPARSE_QUIET_MAP)-1} total specifications of -q and --quiet "
                f"allowed"
            )

        level = _ARGPARSE_QUIET_MAP[quiet_level]

    else:
        # nothing to change
        return

    # basic configuration for the root logger if none has been performed yet
    root_logger = logging.getLogger()
    if not root_logger.hasHandlers():
        formatter = logging.Formatter(
            '{asctime} {levelname:8} {name:24.24} {message}',
            datefmt='%Y-%m-%d %H:%M:%S', style='{'
        )
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(formatter)
        # let the loggers decide on the level
        stderr_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(stderr_handler)

    # tuitfw.loggage -> tuitfw
    parent_name = ".".join(__name__.split(".")[:-1])
    parent_logger = logging.getLogger(parent_name)
    parent_logger.setLevel(level)
