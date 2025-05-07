"""NTFSPE class."""

import logging
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Optional

import graphviz
import numpy as np
import pandas as pd
from dateutil.relativedelta import relativedelta
from sklearn.preprocessing import MinMaxScaler, StandardScaler

from decode.file_graph import SimpleFileGraph
from decode.stats_functions import anomaly_detection, fisher, prob_x

from .config import EXCLUDED_FILES


col_list = [
    "ComputerName",
    "VolumeID",
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
    "SnapshotID",
    "SignedHash",
]


def time_window_management(
    data: pd.DataFrame,
    time_windows: int,
    start_date: Optional[str],
    end_date: Optional[str]
) -> pd.DataFrame:
    """Time window filtering."""
    date_format = "%Y-%m-%d"
    date = datetime.now(timezone.utc)
    if end_date is None:
        end_date = data.FileNameCreationDate.max()
    else:
        end_date = datetime.strptime(
            end_date, date_format
        ).replace(tzinfo=timezone.utc)
    if start_date is None:
        # Manages dates in the future
        if sum(data.FileNameCreationDate > date) > 0:
            logging.warning(
                "%d file(s) have future dates",
                sum(data.FileNameCreationDate > date),
            )
            # No other file
            if sum(data.FileNameCreationDate <= date) > 0:
                last_date = data[
                    data.FileNameCreationDate <= date
                ].FileNameCreationDate.max()
            else:
                last_date = date
            start_date = last_date - relativedelta(months=time_windows)
        else:
            start_date = end_date - relativedelta(months=time_windows)
    else:
        start_date = datetime.strptime(
            start_date, date_format
        ).replace(tzinfo=timezone.utc)
    logging.info("Time window selected: %s - %s", start_date, end_date)
    return start_date, end_date


def _score_normalization(data: pd.DataFrame) -> pd.DataFrame:
    scaler = MinMaxScaler()
    data = scaler.fit_transform(data)
    return data


def _one_hot_encoding(data: pd.DataFrame, attribute: str) -> pd.DataFrame:
    encoded_attribute = pd.get_dummies(data[[attribute]])
    data = pd.concat([data, encoded_attribute], axis=1)
    data = data.drop(attribute, axis=1)
    return data


def _replace_value(data: pd.DataFrame, column_name: str) -> pd.DataFrame:
    data[column_name] = data[column_name].apply(
        lambda x: 1 if not (pd.isna(x) or x == "nan") else 0
    )
    return data


def fullpath_creation(
    data: pd.DataFrame,
    volume: Optional[str]
) -> pd.DataFrame:
    """Transform paths into PureWindowsPath type."""
    data["FullPath"] = [
        PureWindowsPath(x, y) for x, y in zip(data["ParentName"].fillna("\\"), data["File"])
    ]
    if volume and not (pd.isna(volume)):
        data["FullPath"] = [
            PureWindowsPath(volume).joinpath(x) for x in data["FullPath"]
        ]
    return data


def nbfiles_created_at_same_time(
    x: pd.Timestamp,
    dates: pd.Series,
    s: int
) -> int:
    """Reurns the number of files created during the
    +/-s time interval around the date.

    Arguments:
    ---------
    x : pd.Timestamp
        File creationdate.
    dates : pd.Series
        List of file creation dates.
    s: int
        Time interval in minutes.

    Returns:
    -------
    n_files : int

    """
    return len(
        dates[
            dates.between(
                x + pd.offsets.Minute(-s),
                x + pd.offsets.Minute(s),
                inclusive="neither",
            )
        ]
    )


def path_depth(data: pd.DataFrame, column: str) -> pd.DataFrame:
    """Return the depth of the path for a given column.

    Arguments:
    ---------
    data : pd.DataFrame
    column : str
       Column name containing the PureWindowsPath of the files.

    Returns:
    -------
    data : pd.DataFrame
       The DataFrame with the new column.

    """
    data["PathDepth"] = data[column].apply(lambda x: len(x.parents))
    return data


def attributes_processing(data: pd.DataFrame) -> np.ndarray:
    """Preprocess attributes and normalizes the values.

    Filters attributes with constant value.
    If several columns are identical, keep the first one and
    delete the others.
    """
    drop_cols = []
    for col in data.columns:
        array = data[col].to_numpy()
        if array.shape[0] == 0 or (array[0] == array).all():
            drop_cols.append(col)
    data = data.drop(drop_cols, axis=1)
    cols = list(data.var().sort_values(ascending=False).index)
    data = data[cols]
    data = data.T.drop_duplicates().T
    logging.info("Number of features attributes: %d", len(data.columns))
    # Standardization of features
    x = data.to_numpy()
    sc = StandardScaler()
    x_std = sc.fit_transform(x)
    return x_std


class NTFSPE:
    """NTFSPE class."""
    def __init__(
        self,
        ntfs_df: pd.DataFrame,
        time_windows: int = 6,
        volume: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ):
        """Extracts PE files from NTFSInfo over the selected time window,
        enriched and processes the data.

        Arguments:
        ---------
        ntfs_df : pd.DataFrame
            NTFSInfo DataFrame.
        time_windows : int, default=6
            Time window in months from the most recent file creation.
        volume : str
            NTFSInfo volume name
        start_date : str
            Start date if specified.
        end_date : str
            End date if specified

        """
        self.data = ntfs_df
        if self.data.shape[0] == 0:
            logging.warning("Empty NTFSInfo")
            return
        self.data_filtering()
        if self.data.shape[0] == 0:
            logging.warning("Empty NTFSInfo after filtering. Check your NTFSInfo file.")
            return
        self.data.FileNameCreationDate = pd.to_datetime(
            self.data.FileNameCreationDate, utc=True)
        start_date, end_date = time_window_management(
            self.data, time_windows, start_date, end_date
        )
        self.data = self.data[
            (self.data.FileNameCreationDate >= start_date)
            & (self.data.FileNameCreationDate <= end_date)
        ]
        self.data_preprocessing(volume)
        if self.data.shape[0] == 0:
            logging.warning("No PE files found in this time window")
            return
        self.data = self.data.assign(
            Analysis=False,
            Isolated=False,
            isolated_pval=np.nan,
            Features=False,
            Path=False,
            path_pval=np.nan,
            if_features_pval=np.nan,
            db_features=np.nan,
            features_core_pnt=np.nan,
            db_features_pval=np.nan,
            features_pval=np.nan,
            final_score=np.nan,
        )
        self.data_processing()
        self.graph = SimpleFileGraph(self.data.FullPath.copy())

    def data_filtering(self) -> None:
        """Filtering on PE files."""
        # Delete files with FilenameFlags = 2
        boolFlags = self.data["FilenameFlags"] != 2
        self.data = self.data[boolFlags].copy()
        self.data = self.data.drop(columns="FilenameFlags")
        # Keep files with RecordInUse = 'Y'
        boolRecord = self.data["RecordInUse"] == "Y"
        self.data = self.data[boolRecord].copy()
        self.data = self.data.drop(columns="RecordInUse")
        # Delete files without AuthenticodeStatus
        boolArr = self.data["AuthenticodeStatus"].notna()
        self.data = self.data[boolArr].copy()
        # Sort by FileNameCreationDate
        self.data = self.data.sort_values(by=["FileNameCreationDate"])

    def data_preprocessing(self, volume: str) -> None:
        """Add new attributes."""
        if volume:
            self.data["VolumeInfo"] = volume
        else:
            self.data["VolumeInfo"] = np.nan
        self.data = fullpath_creation(self.data, volume)
        self.data["FilesCreatedAtSameTime"] = self.data.FileNameCreationDate.apply(
            lambda x: nbfiles_created_at_same_time(x, self.data.FileNameCreationDate, 1)
        )
        # Remove exclude files in config.py
        for attr, value in EXCLUDED_FILES.items():
            self.data[attr] = self.data[attr].astype(str)
            indexes = self.data.index[
                self.data[attr].str.lower() == value.lower()
            ].to_list()
            self.data = self.data.drop(indexes)

    def data_processing(self) -> None:
        """Processes data for algorithms."""
        self.process_data = self.data.copy()
        self.process_data = path_depth(self.process_data, "FullPath")
        self.process_data = self.process_data[
            [
                "Version",
                "Platform",
                "FileType",
                "FileOS",
                "AuthenticodeStatus",
                "AuthenticodeSignerThumbprint",
                "AuthenticodeCAThumbprint",
                "SignedHash",
                "PathDepth",
                "FilesCreatedAtSameTime",
            ]
        ]
        self.process_data = _one_hot_encoding(self.process_data, "Platform")
        self.process_data["FilesCreatedAtSameTime"] = self.process_data[
            "FilesCreatedAtSameTime"
        ].apply(lambda x: 1 / x)
        _replace_value(self.process_data, "SignedHash")
        _replace_value(self.process_data, "AuthenticodeSignerThumbprint")
        _replace_value(self.process_data, "AuthenticodeCAThumbprint")
        _replace_value(self.process_data, "FileType")
        _replace_value(self.process_data, "FileOS")
        _replace_value(self.process_data, "Version")

    def update_graph(self) -> None:
        """Updates the graph of the NTFSPE object."""
        self.graph = SimpleFileGraph(self.data.FullPath.copy())

    def structural_outliers_research(self) -> None:
        """Detect structural anomalies on the graph.
        Return an isolation score to all files.
        The higher this score is, the more abnormal the file is.

        """
        dict_scores = {}
        dict_scores, outliers = self.graph.structural_outliers()
        scores = pd.Series(list(self.data.FullPath)).map(dict_scores)
        self.data["isolated_pval"] = prob_x(scores.values)
        self.data["Isolated"] = [x in outliers for x in self.data.FullPath]

    def detect_anomalies(self, index: list, contamination: float) -> None:
        """Arguments:
        ---------
        index : list
            Index of files on which we want to launch the detection.
        contamination : int
            The estimated degree of outliers in the dataset.

        """
        x = self.process_data.loc[index, ].copy()
        data = self.data.loc[index, ].copy()
        x = x.drop(columns="AuthenticodeStatus")
        # PATH anomaly detection
        graph = SimpleFileGraph(data["FullPath"].copy())
        dict_scores = {}
        dict_scores, outliers = graph.structural_outliers()
        path_scores = pd.Series(list(data.FullPath)).map(dict_scores)
        data["path_pval"] = prob_x(path_scores.values)
        data["Path"] = [x in outliers for x in data.FullPath]
        # FEATURES anomaly detection
        X_std = attributes_processing(x)
        if_scores, if_labels, db_labels, core_distances = anomaly_detection(
            X_std, contamination
        )
        data["Features"] = (if_labels == -1) | (db_labels == -1)
        data["if_features_pval"] = prob_x(if_scores)
        data["db_features"] = (db_labels == -1).astype(int)
        data["features_core_pnt"] = core_distances
        data["features_core_pnt"] = _score_normalization(data[["features_core_pnt"]])
        db_features_score = data["db_features"] + data["features_core_pnt"]
        data["db_features_pval"] = prob_x(db_features_score.to_numpy())
        data["features_pval"] = data[["if_features_pval", "db_features_pval"]].apply(
            lambda x: fisher(x), axis=1, result_type="expand"
        )
        # Final Score
        data["final_score"] = data[
            ["features_pval", "path_pval", "isolated_pval"]
        ].apply(lambda x: fisher(x), axis=1, result_type="expand")
        data["final_score"] = data["final_score"].apply(lambda x: 1 - x)
        self.data.update(data)

    def anomalies_by_authenticode_status(
        self, contamination: float, min_file: int = 10
    ) -> None:
        """Arguments:
        ---------
        contamination : int
            The estimated degree of outliers in the dataset.
        min_file : int, default=10
            Minimum number of files to start the analysis.
            If the number of files is less than or equal to
            `min_file`, the files are returned with the maximum
            score `1`.

        """
        for status in self.data.AuthenticodeStatus.unique():
            index = self.data.index[self.data.AuthenticodeStatus == status].tolist()
            logging.info("%s class: %d files", status, len(index))
            # SignedNotVerified and Unknwon files
            if status in ["SignedNotVerified", "Unknwon", "Unknown"]:
                self.data.loc[index, "final_score"] = 1
            # NotSigned and SignedVerified files
            elif status in ["NotSigned", "SignedVerified"]:
                if self.data.loc[index, ].shape[0] < min_file:
                    logging.warning("%s: Not enough file to start the analysis",
                                    status)
                    self.data.loc[index, "final_score"] = 1
                else:
                    self.data.loc[index, "Analysis"] = True
                    self.detect_anomalies(index, contamination)
            else:
                logging.warning("%s: Unknown AuthenticodeStatus", status)

    def diagram_generation(
        self, max_files: int, filename: Optional[str] = None
    ) -> graphviz.Digraph:
        """Generates the tree structure with the most abnormal files.
        If there are more than `max_files` files detected, only the
        `max_files` most abnormal files are displayed in the view.

        Arguments:
        ---------
        max_files : int
            Maximum number of anomalies displayed on the diagram
            (for clarity purposes).
        filename : str, default=None
            Filename of the generated file.

        Returns:
        -------
        H : graphviz.Digraph
            Object containing the DOT language representation of the
            file tree with the most abnormal files detected.

        """
        first_outliers = self.data.sort_values(
            by="final_score",
            ascending=False
        )[:max_files].copy()
        logging.info(
            "Number of files displayed on the diagram: %d", len(first_outliers)
        )
        path_outliers = [
            x
            for x, y in zip(first_outliers.FullPath, first_outliers.Path)
            if (isinstance(y, bool) and y is True)
        ]
        features_outliers = [
            x
            for x, y in zip(first_outliers.FullPath, first_outliers.Features)
            if (isinstance(y, bool) and y is True)
        ]
        isolated_outliers = [
            x
            for x, y in zip(first_outliers.FullPath, first_outliers.Isolated)
            if (isinstance(y, bool) and y is True)
        ]
        min_files_outliers = [
            x for x, y in zip(first_outliers.FullPath, first_outliers.Analysis)
            if not y
        ]
        outliers_dict = {
            "P": path_outliers,
            "F": features_outliers,
            "I": isolated_outliers,
            "X": min_files_outliers,
        }
        # Summarized view of the tree structure
        h = self.graph.coarsened_tree(
            min_proportion=0.05,
            file_subset=first_outliers.FullPath
        )
        H = h.draw(
            displayed_files=outliers_dict,
            max_displayed_files=max_files,
            filename=filename
        )
        return H

    def delete_authenticode_status_class(
        self, authenticode_class: str
    ) -> None:
        """Deletes the files of the AuthenticodeStatus class."""
        if authenticode_class in self.data.AuthenticodeStatus.unique():
            self.data = self.data[
                self.data.AuthenticodeStatus != authenticode_class
            ].copy()
            self.process_data = self.process_data[
                self.process_data.AuthenticodeStatus != authenticode_class
            ].copy()


def read_ntfs_from_csv(ntfs_file: Path) -> pd.DataFrame:
    """Create a DataFrame from a CSV file."""
    ntfs = pd.read_csv(
        ntfs_file,
        usecols=col_list,
        header=0,
        low_memory=False,
        na_values="",
        keep_default_na=False,
    )
    return ntfs
