
# Dataset

The `dataset/` folder provides a sample of a use case to easily test the tool.

DFIR-ORC was launched on a compromised system and the following files were extracted from the ORC archives:
* NTFSInfo_00000000_DiskInterface_0x94303d7b303d6600_.csv.gz ("C:\" volume)
* volstats.csv
* ListDlls.txt

The `malwares.txt` file contains the malicious files dropped by the attacker.

To start the analysis:
```
machine_analysis NTFSInfo_00000000_DiskInterface_0x94303d7b303d6600_.csv.gz --csv_output Results_data.csv  --pdf_output file_tree.pdf --dlls_file Listdlls.txt 
```


NB: You can exclude the collection tool files from analysis by editing the file `src/decode/config.py`:  
"EXCLUDED_FILES = {attribut: value}"