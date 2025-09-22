# TESTING the wiskess commands
These are several commands to run wiskess with to confirm it is working.

## Build
Confirm it builds without any error.
```
cargo build --release
```

## Setup
Run setup without any flags. Confirm it asks for a github token, and continues to run setup.
```
.\wiskess_rust.exe setup
```

Run setup with an invalid github token. Confirm it:
* is unable to download the latest release of packages including hayabusa, chainsaw, evtx, loki, etc.
* asks the user for the right token, if the token doesn't start with `github_pat_`
```
.\wiskess_rust.exe setup -g 'invalid'
```

Run setup with a valid token. Confirm it runs and installs all needed packages.
```
.\wiskess_rust.exe setup -g 'github_pat_11 ... LlVIgO'
```

Run setup check to scan most of the installed packages.
Confirm it reports `[+] Check complete. Wiskess is setup OK.`
```
.\wiskess_rust.exe setup -c
```

## Wiskess
Run wiskess with an invalid start or end date. Confirm it asks for a valid start and end data:
```
.\wiskess_rust.exe wiskess --start-date 01-05-2023 --end-date 20025-07-16 -d C: --out-path C:\C-Wiskess --ioc-file .\iocs.txt
```

Run wiskess with an invalid data source, i.e. doesn't exist `Z:`. Confirm it asks `What is the file path of base?`, and the rest of the unknown paths:
```
.\wiskess_rust.exe wiskess --start-date 2023-01-05 --end-date 2025-07-16 -d Z: --out-path C:\C-Wiskess --ioc-file .\iocs.txt
```

Run wiskess with an output folder that doesn't exist. Confirm it creates the output folder.
```
.\wiskess_rust.exe wiskess --start-date 2023-01-05 --end-date 2025-07-16 -d Z: --out-path C:\NEW_OUTPUT_FOLDER_TEST --ioc-file .\iocs.txt
```

Run wiskess to process a mounted disk image. Confirm it creates an artefacts folder under the output path, i.e. "X:\DC01-Wiskess\Artefacts", and collects artefacts that it can't directly read to that folder. Then processes the disk image from either the collected files or the oringinal mounted source. 
```
.\wiskess_rust.exe wiskess --start-date 2025-04-01 --end-date 2025-07-16 -d F: --out-path X:\DC01-Wiskess --ioc-file .\iocs.txt
```

Run wiskess to process a velociraptor collection, which has been extracted and with files moved into one folder.
```
.\wiskess_rust.exe wiskess --start-date 2025-04-01 --end-date 2025-07-16 -d X:\Collection-myhost-2025-07-15T20_41_49Z\uploads\files\ --out-path X:\Collection-myhost-2025-07-15T20_41_49Z-Wiskess --ioc-file .\iocs.txt
```

## Whipped
Run whipped with a valid azure SAS token as the in and out links. Confirm all the data is processed and uploaded to the out link.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 
```

Run whipped with a valid AWS credentials stored in the terminal's session, and specify the AWS S3 bucket as the in and out links. Confirm all the data is processed and uploaded to the out link.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "s3://my-collections/input" --out-link "s3://my-collections/output" --start-date 2025-01-01 --end-date 2025-08-15 
```

Run whipped targetting one collection.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "Collection-DC.zip"
```

Run whipped targetting multiple collections.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "Collection-DC.zip,Collection-FTP.zip,Collection-FW.zip"
```

Run whipped targetting multiple collections in child folders.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "Collection-DC.zip,velo/Collection-FTP.zip,storage/Collection-FW.zip"
```

Run whipped targetting a disk image. When complete it should archive the artefacts in the artefacts folder to a file "collection.zip".
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "DC.vmdk"
```

Run whipped targetting a disk image in an archive.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "DC-vmdk-image.zip"
```

Run whipped with the update flag. Make sure the data had been processed already, that the collection.zip is extracted (if a disk image) and the folders timeline, ioc findings, 
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "Collection-DC.zip" --update
```

Run whipped with the keep-evidence to one evidence item. Confirm the evidence is not deleted.
```
.\wiskess_rust.exe whipped -l C:\test-wiskess\ --in-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test_wiskess?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --out-link "https://myaccount.blob.core.windows.net/gavin-hull-temp/test-wiskess-output?sp=racwl&st=2025-08-25T11:00:31Z&se=2025-09-22T19:15:31Z&spr=https&sv=2024-11-04&sr=c&sig=..." --start-date 2025-01-01 --end-date 2025-08-15 -d "Collection-DC.zip" --keep-evidence
```

## Gui
Run the gui. Confirm it creates the webserver locally and both wiskess and whipped pages function.
```
.\wiskess_rust.exe gui
```

## OldWhip
Run oldwhip and confirm it functions with whipped using the whipped.ps1 script.