"""Provides the main functions to detect abnormal PE in a NTFSInfo file."""

import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import graphviz
import numpy as np
import pandas as pd
import py7zr

from .config import CONTAMINATION, MIN_FILE
from .dll import read_list_dlls_from_txt
from .ntfs_pe import NTFSPE, read_ntfs_from_csv


DEFAULT_CSV_OUTPUT = "Results_data.csv"
DEFAULT_PDF_OUTPUT = "file_tree.pdf"


def search_volume_info(ntfs_file: Path) -> pd.Series:
    """Retrieves in volstats.csv the volume name
    of the NTFSInfo file.

    Arguments:
    ----------
    ntfs_file: Path
    """
    ntfsinfo_filename = re.sub(r"\.gz$", "", ntfs_file.name)
    volstat_file = ntfs_file.parent / "volstats.csv"
    if volstat_file.is_file():
        volstats = pd.read_csv(volstat_file)
        if (pd.Series(
            ["FileInfo", "MountPoint"]
        ).isin(volstats.columns).all()):
            for _, row in volstats.iterrows():
                if isinstance(row["FileInfo"], str) and ntfsinfo_filename in row["FileInfo"]:
                    logging.info("Volume info: %s", row["MountPoint"])
                    return row["MountPoint"]
        else:
            logging.debug("%s not in volstat.csv",
                          ([i for i in ["FileInfo", "MountPoint"]
                            if i not in volstats.columns]))
    return None


def add_list_dlls(ntfs: NTFSPE, list_dlls_file: Path) -> NTFSPE:
    """Adds a new attribute WarningInListDLLs that detects
    if warnings are present ListDlls.

    Arguments:
    ----------
    ntfs: NTFSPE
    list_dlls_file: Path.
    """
    list_dlls = read_list_dlls_from_txt(list_dlls_file)
    if list_dlls and not list_dlls.data.empty:
        in_list_dlls = ntfs.data.FullPath.isin(
            list_dlls.data[list_dlls.data.warning].path.unique()
        )
        ntfs.data["WarningInListDLLs"] = in_list_dlls
        ntfs.process_data["WarningInListDLLs"] = in_list_dlls
        logging.debug("ListDlls file processing")
        logging.debug("Number of warning found in ListDlls: %d",
                      sum(in_list_dlls) if (sum(in_list_dlls) > 0) else 0)
    return ntfs


def prepare_orc(
    orc_file: Path,
    list_dlls_file: Optional[Path] = None,
    time_windows: int = 6,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    output_csv: str = DEFAULT_CSV_OUTPUT,
    output_pdf: str = DEFAULT_PDF_OUTPUT,
) -> None:
    """Prepares the ORC archive for analysis.

    Arguments:
    ----------
    orc_file : Path object
        Path to the ORC archive.
    list_dlls_file : Path object
        Path to the ListDLLs input file
    time_windows: int, default=6
        Time window in months from the most recent file creation.
    start_date : str
        Start date if specified.
    end_date : str
        End date if specified
    output_csv : str, default="Results_data.csv"
        Path of the CSV output file.
        It contains almost the same content as the NTFSInfo input
        file with the score of each file.
        Files with an AuthenticodeStatus `CatalogSignedVerified`
        are filtered.
        The higher this score, the more abnormal the file.
        Maximum score is `1`.
    output_pdf : str, default="file_tree.pdf"
        Path of the graph PDF output file.

    """
    logging.info("Preparing ORC archive %s", orc_file)
    temp_dir = Path(tempfile.mkdtemp(prefix="decode_"))
    logging.debug("Extracting ORC archive to temporary directory %s", temp_dir)
    with py7zr.SevenZipFile(orc_file, mode="r") as archive:
        # Looking for NTFSInfo_details archive and ListDLLs file (if not already
        # provided) in the ORC archive
        ntfsinfo_file = None
        for name in archive.getnames():
            basename = Path(name).name
            if basename in ("NTFSInfo_details.7z", "NTFSInfo_detail.7z"):
                ntfsinfo_file = temp_dir / basename
                archive.extract(targets=[name], path=temp_dir)
                archive.reset()
                logging.debug("NTFSInfo_details archive found: %s", ntfsinfo_file)
            elif list_dlls_file is None and basename == "Listdlls.txt":
                list_dlls_file = temp_dir / basename
                archive.extract(targets=[name], path=temp_dir)
                archive.reset()
                logging.debug("ListDLLs file found: %s", list_dlls_file)
    if ntfsinfo_file is None:
        logging.critical("NTFSInfo_details archive not found in ORC archive.")
        return
    # Extracting the NTFSInfo_details archive and processing it
    with py7zr.SevenZipFile(ntfsinfo_file, mode="r") as archive:
        archive.extractall(path=temp_dir / "ntfsinfo_details")
        archive.reset()

    # For each NTFSInfo file, we launch the analysis
    for ntfsinfo_file in (temp_dir / "ntfsinfo_details").glob("NTFSInfo_*.csv"):
        logging.debug("Processing NTFSInfo file: %s", ntfsinfo_file.name)
        out_csv_path = Path(output_csv)
        out_pdf_path = Path(output_pdf)
        prefixed_output_csv = str(
            out_csv_path.parent / f"{ntfsinfo_file.stem}{out_csv_path.name}"
        )
        prefixed_output_pdf = str(
            out_pdf_path.parent / f"{ntfsinfo_file.stem}{out_pdf_path.name}"
        )
        analyse(
            ntfsinfo_file,
            list_dlls_file=list_dlls_file,
            time_windows=time_windows,
            start_date=start_date,
            end_date=end_date,
            output_csv=prefixed_output_csv,
            output_pdf=prefixed_output_pdf,
        )

    # Cleaning up the temporary directory
    logging.debug("Cleaning up temporary directory %s", temp_dir)
    shutil.rmtree(temp_dir)


def analyse(
    ntfs_file: Path,
    list_dlls_file: Optional[Path] = None,
    time_windows: int = 6,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    output_csv: str = DEFAULT_CSV_OUTPUT,
    output_pdf: str = DEFAULT_PDF_OUTPUT,
) -> None:
    """Ranking of PE files according to their level of abnormality.
    The higher the score of a file, the more abnormal the file is.
    The analysis is launched only if the number of files is greater
    than the value of `min_file`.
    CatalogSignedVerified files are considered benign and are not
    analyzed.

    Arguments:
    ----------
    ntfs_file : Path object
        Path to the NTFSInfo input file.
    list_dlls_file : Path object
        Path to the ListDLLs input file
    time_windows: int, default=6
        Time window in months from the most recent file creation.
    start_date : str
        Start date if specified.
    end_date : str
        End date if specified
    contamination : float, default=0.02
        The estimated amount of outliers in the dataset.
    min_file : int, default=10
        Minimum number of files to launch the analysis.
    output_csv : str, default="Results_data.csv"
        Path of the CSV output file.
        It contains almost the same content as the NTFSInfo input
        file with the score of each file.
        Files with an AuthenticodeStatus `CatalogSignedVerified`
        are filtered.
        The higher this score, the more abnormal the file.
        Maximum score is `1`.
    output_pdf : str, default="file_tree.pdf"
        Path of the graph PDF output file.

    """
    contamination = CONTAMINATION
    min_file = MIN_FILE
    ntfs_df = read_ntfs_from_csv(ntfs_file)
    volume_name = search_volume_info(ntfs_file)
    ntfs = NTFSPE(
        ntfs_df=ntfs_df,
        time_windows=time_windows,
        volume=volume_name,
        start_date=start_date,
        end_date=end_date,
    )
    logging.debug("File count: %d", ntfs.data.shape[0])
    if ntfs.data.shape[0] != 0:
        # ListDLLs
        ntfs.data["WarningInListDLLs"] = np.nan
        if list_dlls_file:
            ntfs = add_list_dlls(ntfs, list_dlls_file)
        # Not enough files to start analysis
        if ntfs.data.shape[0] < min_file:
            logging.warning("Not enough files to analyze: %d files",
                            ntfs.data.shape[0])
            # We do not return the CatalogSignedVerified files
            ntfs.delete_authenticode_status_class("CatalogSignedVerified")
            ntfs.data["final_score"] = 1
            ntfs.data.to_csv(output_csv, na_rep="NaN", index=False)
        else:
            # Structural outliers research
            ntfs.structural_outliers_research()
            # We remove the CatalogSignedVerified files
            ntfs.delete_authenticode_status_class("CatalogSignedVerified")
            ntfs.update_graph()
            # Outliers research by cluster analysis
            ntfs.anomalies_by_authenticode_status(contamination, min_file)
            ntfs.data = ntfs.data.sort_values(
                by="final_score",
                ascending=False
            )
            # Generate the tree diagram
            H = ntfs.diagram_generation(60)
            try:
                H.render(outfile=output_pdf, cleanup=True)
            except graphviz.backend.execute.ExecutableNotFound:
                logging.exception("Missing executable: %s")
            ntfs.data.to_csv(output_csv, na_rep="NaN", index=False)
    logging.info("End of analysis")
