"""Module for command line interface."""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import NoReturn, Optional, Sequence

from .core import DEFAULT_CSV_OUTPUT, DEFAULT_PDF_OUTPUT, analyse, prepare_orc
from .info import __copyright__, __description__, __issues__, __version__


os.environ["OPENBLAS_NUM_THREADS"] = "1"
LOG_LEVELS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
logger = logging.getLogger(__name__)


def setup_logging(
    log_file: Optional[str] = None,
    log_level: Optional[str] = None,
) -> None:
    """Do setup logging to redirect to log_file at DEBUG level."""
    if log_level is None:
        log_level = "INFO"

    # Setup logging
    if log_file:
        # Send everything (DEBUG included) in the log file
        # and keep only log_level messages on the console
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)-8s - %(name)s - %(message)s",
            filename=log_file,
            filemode="w",
        )
        # define a Handler which writes messages of log_level
        # or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(log_level)
        # set a format which is simpler for console use
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s - %(message)s",
        )
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logging.root.addHandler(console)
    else:
        logging.basicConfig(
            level=log_level,
            format="[%(asctime)s] %(levelname)-8s - %(message)s",
        )


class HelpArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser for different exit-code on error."""

    def error(self, message: str) -> NoReturn:
        """Handle error from argparse.ArgumentParser."""
        self.print_help(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def get_parser() -> argparse.ArgumentParser:
    """Prepare ArgumentParser."""

    def existing_file(string: str) -> Path:
        p = Path(string)
        if p.exists():
            if p.is_file():
                return p
            msg = "Invalid file type: must be a file"
            raise argparse.ArgumentTypeError(msg)
        msg = "No such file"
        raise argparse.ArgumentTypeError(msg)

    parser = HelpArgumentParser(
        prog="decode",
        description=__description__,
        epilog=f"{__version__} - {__copyright__}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s, version {__version__}",
    )
    parser.add_argument(
        "--log-level",
        metavar="level",
        default="INFO",
        choices=LOG_LEVELS,
        help=(
            "print log messages of this level and higher, possible choices: %(choices)s"
        ),
    )
    parser.add_argument(
        "--log-file",
        metavar="file",
        help="log file to store DEBUG level messages",
    )
    parser.add_argument(
        "--csv_output",
        metavar="STRING",
        type=str,
        help="""path to the results output (CSV document)""",
        default=DEFAULT_CSV_OUTPUT,
    )
    parser.add_argument(
        "--pdf_output",
        metavar="STRING",
        type=str,
        help="""path to the visualization output (PDF document)""",
        default=DEFAULT_PDF_OUTPUT,
    )
    parser.add_argument(
        "file_to_process",
        metavar="FILE",
        type=existing_file,
        help="""NTFSInfo file OR DFIR-Orc archive to process""",
    )
    parser.add_argument(
        "--dlls_file",
        metavar="FILE",
        type=existing_file,
        help="""ListDLLs file to process""",
    )
    parser.add_argument(
        "--start_date",
        metavar="DATE",
        help="""start date of the analysis time window in the format Y-m-d""",
    )
    parser.add_argument(
        "--end_date",
        metavar="DATE",
        help="""end date of the analysis time window in the format Y-m-d""",
    )
    parser.add_argument(
        "--time_window",
        metavar="INT",
        type=int,
        help="""time window (in months) preceding the last date identified to consider""",
        default=6,
    )
    return parser


def entrypoint(argv: Optional[Sequence[str]] = None) -> None:
    """Entrypoint for command line interface."""
    try:
        parser = get_parser()
        args = parser.parse_args(argv)
        setup_logging(args.log_file, args.log_level)

        if args.file_to_process.suffix == ".7z":
            prepare_orc(
                args.file_to_process,
                list_dlls_file=args.dlls_file,
                time_windows=args.time_window,
                start_date=args.start_date,
                end_date=args.end_date,
                output_csv=args.csv_output,
                output_pdf=args.pdf_output,
            )
        else:
            analyse(
                args.file_to_process,
                list_dlls_file=args.dlls_file,
                time_windows=args.time_window,
                start_date=args.start_date,
                end_date=args.end_date,
                output_csv=args.csv_output,
                output_pdf=args.pdf_output,
            )
    except Exception as err:
        logger.critical("Unexpected error", stack_info=True, exc_info=err)
        logger.critical("Please report this error to : %s", __issues__)
        sys.exit(1)
