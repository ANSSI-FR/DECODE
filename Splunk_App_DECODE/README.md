# Splunk App for DECODE

This package is a dashboard app for Splunk to exploit results of [DECODE](https://github.com/ANSSI-FR/DECODE) tool.

There is no package requirements to install the app.

## Installation

Copy this current folder `Splunk_App_DECODE` into `$SPLUNK_HOME/etc/apps/`.

## Data ingestion

This app adds a sourcetype `anssi:decode` (described in `props.conf` file) corresponding to DECODE results.  

In order to add data, you can :
- manually add single a file :
```
./splunk add oneshot "/path/to/decode/results/folder/hostname.csv" -sourcetype "anssi:decode" -index ##INDEX_NAME## -host ##HOSTNAME##
```

- monitor a folder (add configuration in the file `inputs.conf`) :

```
[monitor:///path/to/decode/results/folder/]
disabled = false
host_regex = /([^/]+)\.csv
sourcetype = anssi:decode
index = ##INDEX_NAME##
crcSalt = <SOURCE>
```