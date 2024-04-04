

# DECODE

<img src="./decode.png" width="150">

DECODE, or "DEtection de COmpromissions dans les DonnéEs DFIR-ORC" in French, is a stand-alone tool specifically designed for detecting anomalous Portable Executable (PE) files among the NTFSInfo data collected by DFIR-ORC on Microsoft Windows system.

This tool ranks PE files found on a machine from most to least anomalous, allowing forensic analysts to prioritize their efforts during incident response or compromise assessment.

Anomaly scores are computed using both traditional outlier detection algorithms and graph-based anomaly detection. Our approach only leverages file metadata, avoiding in-depth analysis of the binary content of the PEs. In addition, it does not rely on pre-trained machine learning models and adapts easily to new systems and attacks.

The tool provides two visualization modules to interpret results:
* a simplified view of the tree structure with the most anomalous PEs
* a Splunk dashboard app which can be integrated into your Splunk platform for results analysis

DECODE was developed to analyze NTFSInfo data collected by DFIR-ORC, a forensic tool developed by ANSSI that you can find [here](https://github.com/DFIR-ORC/dfir-orc).

This tool was presented at the DFRWS 2024 conference.


## Usage

To start the analysis:

```bash
machine_analysis NTFSInfo_FILE --csv_output Results_data.csv  --pdf_output file_tree.pdf
```

* NTFSInfo_FILE: NTFSInfo file collected by DFIR-ORC in csv format;

Optional parameters:

  * --version: show program's version number and exit;

  * --log-level (level): print log messages of this level and higher, possible choices: CRITICAL, ERROR, WARNING, INFO, DEBUG;

  * --log-file file: log file to store DEBUG level messages;

  * --csv_output (str): path to the results output (*Results_data.csv* by default). The output is a CSV document;

  * --pdf_output (str): path to the visualization output (*file_tree.pdf* by default). The output is a PDF document containing a tree-based visual display of the results;

  * --start_date/--end_date: customization of the time window in "Y-m-d" format. If the dates are not specified, the function analyzes the last time_windows months of the machine by default;

  * --time_window (int): time window (in months) to consider during the analysis. By default it is set to 6, which represents the 6 months preceding the latest date identified in the MFT;

  * --min_files (int): minimum number of files required to start the analysis, by default set to 10. If the number of files is lower, the algorithms are not launched and all the files are reported with the maximum abnormality score of 1;

  * --contamination (float): proportion of outliers (0.02 by default). The top-n files in the anomaly ranking are flagged as outliers, where n equals contamination * (total number of files).

Example:

```bash
machine_analysis NTFSInfo.csv --csv_output Results_data.csv  --pdf_output file_tree.pdf --start_date 2019-01-18 --end_date 2019-09-01
```

## Presentation
* Helcmanocki, Lucie. "Decode: Anomaly Detection for PE Files on Microsoft Windows Systems", DFRWS EU 2024

## Authors
* Lucie Helcmanocki
* Corentin Larroche
* Roger Guignard
* Rémi Chauchat

## References
__DFIR ORC documentation__: https://dfir-orc.github.io
