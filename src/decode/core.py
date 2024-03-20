"""Provides the main functions to detect abnormal PE in a NTFSInfo file."""

import logging
from pathlib import Path
from typing import Optional

import graphviz

from .ntfs_pe import NTFSPE


col_list = [
    "ComputerName",
    "File",
    "ParentName",
    "Extension",
    "SizeInBytes",
    "Attributes",
    "CreationDate",
    "LastModificationDate",
    "LastAccessDate",
    "LastAttrChangeDate",
    "FileNameCreationDate",
    "FileNameLastModificationDate",
    "FileNameLastAccessDate",
    "FileNameLastAttrModificationDate",
    "RecordInUse",
    "SHA1",
    "Version",
    "OriginalFileName",
    "Platform",
    "TimeStamp",
    "SubSystem",
    "FileType",
    "FileOS",
    "FilenameFlags",
    "PeSHA1",
    "PeSHA256",
    "AuthenticodeStatus",
    "AuthenticodeSigner",
    "AuthenticodeSignerThumbprint",
    "AuthenticodeCA",
    "AuthenticodeCAThumbprint",
    "PeMD5",
    "SignedHash",
]
DEFAULT_CSV_OUTPUT = "Results_data.csv"
DEFAULT_PDF_OUTPUT = "file_tree.pdf"


def analyse(
    ntfs_file: Path,
    time_windows: int = 6,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    contamination: float = 0.02,
    min_file: int = 10,
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
    output_pdf : str, default="file_tree.gv.pdf"
        Path of the graph PDF output file.

    """
    ntfs = NTFSPE(
        ntfs_file=ntfs_file,
        time_windows=time_windows,
        start_date=start_date,
        end_date=end_date,
    )

    logging.debug("File count: %d", ntfs.data.shape[0])
    if ntfs.data.shape[0] < min_file:
        logging.warning("Not enough files to analyze: %d files", ntfs.data.shape[0])
        # We do not return the CatalogSignedVerified files
        ntfs.data = ntfs.data[
            ntfs.data.AuthenticodeStatus != "CatalogSignedVerified"
        ].copy()
        ntfs.data["final_score"] = 1
        ntfs.data.to_csv(output_csv, na_rep="NaN", index=False)
        return
    # Structural outliers research
    ntfs.structural_outliers_research()
    # We do not analyze the CatalogSignedVerified class
    if "CatalogSignedVerified" in ntfs.data.AuthenticodeStatus.unique():
        ntfs.data = ntfs.data[
            ntfs.data.AuthenticodeStatus != "CatalogSignedVerified"
        ].copy()
        ntfs.process_data = ntfs.process_data[
            ntfs.process_data.AuthenticodeStatus != "CatalogSignedVerified"
        ].copy()
        ntfs.update_graph()
    # Outliers research by cluster analysis
    ntfs.anomalies_by_authenticode_status(contamination, min_file)
    ntfs.data = ntfs.data.sort_values(by="final_score", ascending=False)
    # Generate the tree diagram
    H = ntfs.diagram_generation(60)
    try:
        H.render(outfile=output_pdf, cleanup=True)
    except graphviz.backend.execute.ExecutableNotFound:
        logging.exception("Missing executable: %s")
    # Save the results of all the classes in a csv file
    ntfs.data.to_csv(output_csv, na_rep="NaN", index=False)
    logging.info("End of analysis")
