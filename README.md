

# DECODE

<img src="./decode.png" width="150">

DECODE, or "DEtection de COmpromissions dans les DonnéEs DFIR-ORC" in French, is a stand-alone tool specifically designed for detecting anomalous Portable Executable (PE) files among the NTFSInfo data collected by DFIR-ORC on Microsoft Windows system.

This tool ranks PE files found on a machine from most to least anomalous, allowing forensic analysts to prioritize their efforts during incident response or compromise assessment.

Anomaly scores are computed using both traditional outlier detection algorithms and graph-based anomaly detection. Our approach only leverages file metadata, avoiding in-depth analysis of the binary content of the PEs. In addition, it does not rely on pre-trained machine learning models and adapts easily to new systems and attacks.

The tool provides two visualization modules to interpret results:
* a simplified view of the tree structure with the most anomalous PEs
* a Splunk dashboard app which can be integrated into your Splunk platform for results analysis

<center>
<img src="./doc/splunk_dashboard1.png" width="900">
</center>

DECODE was developed to analyze NTFSInfo and ListDlls data collected by [DFIR-ORC](https://github.com/DFIR-ORC/dfir-orc), a forensic tool developed by ANSSI.

This tool was presented at the DFRWS 2024 conference.

## Installation

You need to have graphviz installed on your machine. You can install it through the package manager of your distribution.

For example with Debian/ubuntu:

```
apt install graphviz
```
To install DECODE:
```
git clone https://github.com/ANSSI-FR/DECODE.git
cd DECODE
pip install .
```

## Usage

To start the analysis:

```bash
machine_analysis NTFSInfo_FILE --csv_output Results_data.csv --pdf_output file_tree.pdf
```

* NTFSInfo_FILE: NTFSInfo file collected by DFIR-ORC in csv format;
* --csv_output (str): path to the results output (*Results_data.csv* by default). The output is a CSV document;

Optional parameters:

  * --version: show program's version number and exit;

  * --log-level (level): print log messages of this level and higher, possible choices: CRITICAL, ERROR, WARNING, INFO, DEBUG;

  * --log-file file: log file to store DEBUG level messages;

  * --pdf_output (str): path to the visualization output (*file_tree.pdf* by default). The output is a PDF document containing a tree-based visual display of the results;

  * --dlls_file (str): ListDLLs file in txt format from DFIR-ORC;
    * ListDLLs file can be generated by DFIR-ORC (archive [General](https://github.com/DFIR-ORC/dfir-orc-config/blob/master/config/DFIR-ORC_config.xml#L153), keyword [Listdll](https://github.com/DFIR-ORC/dfir-orc-config/blob/master/config/DFIR-ORC_config.xml#L196)), by using [ListDLLs](https://learn.microsoft.com/fr-fr/sysinternals/downloads/listdlls) Sysinternals tools;

  * --start_date/--end_date: customization of the time window in "Y-m-d" format. If the dates are not specified, the function analyzes the last time_windows months of the machine by default;

  * --time_window (int): time window (in months) to consider during the analysis. By default it is set to 6, which represents the 6 months preceding the latest date identified in the MFT.

Example:

```bash
machine_analysis NTFSInfo.csv --csv_output Results_data.csv  --pdf_output file_tree.pdf --dlls_file Listdlls.txt --start_date 2019-01-18 --end_date 2019-09-01
```

Some parameters can be modified in the src/decode/config.py file:

* CONTAMINATION (float): proportion of outliers (0.02 by default). The top-n files in the anomaly ranking are flagged as outliers, where n equals contamination * (total number of files);

* MIN_FILE (int): minimum number of files required to start the analysis, by default set to 10. If the number of files is lower, the algorithms are not launched and all the files are reported with the maximum abnormality score of 1;

* EXCLUDED_FILES: files to filter before analysis.

**How to generate `NTFSInfo.csv` and `Listdlls.txt` files ?**  
Theses files are generated by [DFIR-ORC](https://github.com/DFIR-ORC/dfir-orc), using the [default configuration](https://github.com/DFIR-ORC/dfir-orc-config) :
- `Listdlls.txt` from `General` archive
- `NTFSInfo.csv` (one CSV by NTFS volume) are in multiple archives, but you must use those present in  `NTFSInfo_detail.7z` from `Details` archive

A default configuration of `DFIR-Orc.exe` (launched without any option) will produce these files and archives. If you only want these files generated by DFIR-Orc, you can use these options :
```
.\DFIR-Orc.exe /key=Listdlls /key=NTFSInfoDetail_systemdrive
```

## Presentation
* Helcmanocki, Lucie. "Decode: Anomaly Detection for PE Files on Microsoft Windows Systems", DFRWS EU 2024

## Authors
* Lucie Helcmanocki
* Corentin Larroche
* Roger Guignard
* Rémi Chauchat

## References
__DFIR-ORC__: https://github.com/dfir-orc

__DFIR-ORC documentation__: https://dfir-orc.github.io
