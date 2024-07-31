"""Provides the main functions to detect abnormal PE in a NTFSInfo file."""

import logging
from pathlib import Path
from typing import Optional

import graphviz
import pandas as pd

from .config import CONTAMINATION, MIN_FILE
from .dll import read_list_dlls_from_json, read_list_dlls_from_txt
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
    file_name = "volstats.csv"
    for file in ntfs_file.parent.iterdir():
        if (file.is_file() and file.name == file_name):
            volstats = pd.read_csv(file)
            if (pd.Series(["FileInfo", "MountPoint"]).isin(volstats.columns).all()):
                return volstats[volstats.FileInfo == ntfs_file.name]["MountPoint"].item()
    return None


def add_list_dlls(ntfs: NTFSPE, list_dlls_file: Path) -> NTFSPE:
    """Adds a new attribute WarningInListDLLs that detects
    if warnings are present ListDlls.

    Arguments:
    ----------
    ntfs: NTFSPE
    list_dlls_file: Path.
    """
    if list_dlls_file.suffix.lower() == ".json":
        list_dlls = read_list_dlls_from_json(list_dlls_file)
    elif list_dlls_file.suffix.lower() == ".txt":
        list_dlls = read_list_dlls_from_txt(list_dlls_file)
    if list_dlls and not list_dlls.data.empty:
        in_list_dlls = ntfs.data.FullPath.isin(
            list_dlls.data[list_dlls.data.warning].path.unique()
        )
        ntfs.data["WarningInListDLLs"] = 0
        ntfs.data["WarningInListDLLs"] = in_list_dlls
        ntfs.process_data["WarningInListDLLs"] = in_list_dlls
    return ntfs


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
        end_date=end_date
    )
    logging.debug("File count: %d", ntfs.data.shape[0])
    if ntfs.data.shape[0] != 0:
        # If ListDLLs file was passed
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
