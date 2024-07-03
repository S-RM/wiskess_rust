# wiskess_rust
WISKESS automates the Windows evidence processing for Incident Response investigations. Rust version is a program that has been developed with enhanced parallel processing and reliability.

This is the Rust version of WISKESS, which uses parallel processing of multiple tools and more can be added. The list of tools used after setup are:

ANSSI-FR: bmc_tools

Nir Soft: BrowsingHistoryView

Yamato-Security: hayabusa

obsidianforensics: hindsight

brimorlabs: KStrike

Neo23x0: loki

BurntSushi: RipGrep

keydet89: RegRipper

williballenthin: shellbags

davidpany: 
- CCM_RUA_Finder
- PyWMIPersistenceFinder

omerbenamram:
- evtx
- mft

WithSecureLabs chainsaw:
- evtx
- Shimcache
- SRUM (System Resource Usage Monitor)

EZTools:
- AmcacheParser
- AppCompatCacheParser
- EvtxECmd
- JLECmd
- LECmd
- MFTECmd
- PECmd
- RBCmd
- RecentFileCacheParser
- RECmd
- SBECmd
- SrumECmd
- SumECmd

S-RM:
- enrich
- polars_enrich.py
- polars_hostinfo.py
- polars_tln.py
- Executablelist.ps1

Whipped Tools:
- AzCopy
- 7zip
- OSFMount

It includes enrichment tools that scan the data source using your IOC list, yara rules, and open source intelligence. 

The results are structured into folders in CSV files that can be opened with text editors and searched across using tools like grep. The tool produces a report of the system info and files that have produced results in the Analysis folder.

The output is generated into reports of a timeline that is compatible with ingesting into visualisation tools including, timesketch, elastic and splunk.

![271793948-27e9b4b3-0a7f-4efb-a844-2eda7a8a6385](https://github.com/vividDuck/wiskess_rust/assets/122105925/46cacffc-a0d0-4ec7-b1cb-60bca314d2bb)

# Requirements
run `wiskess_rust.exe setup -g <your github token>` using a terminal with Administrator rights. 

The github token needs the minimum permissions to access public github repos. GitHub's guide is here: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token

# Whipped by WISKESS `wiskess_rust.exe whipped`
This command will pull data from an AWS or Azure store, process it with wiskess and upload the output to a store.

## Usage
This can be used to process Windows data sources stored on either an Azure or AWS S3 cloud account. It can also be used to process data from a network share or local drive.

### Azure Usage:
* Generate a SAS key from the storage where the data is stored in azure
* Generate a SAS key to where you need the Wiskess output to be uploaded to in azure
* Copy the file path of all the data you need processed, this needs to be the same as the path in Azure
* Set a start and end time, which is likely the incident timeframe

### AWS Usage:
* Add to your session or terminal the AWS credentials for the account where the data is stored in S3
* Get the s3:// link to where the data source is stored
* Create a bucket or folder in AWS S3, where you need the Wiskess output to be uploaded to in azure. Get that s3:// link too.        
* Copy the file path of all the data you need processed, this needs to be from the folder or bucket that you got the s3:// link.     
* Set a start and end time, which is likely the incident timeframe

## Example
```
wiskess_rust.exe whipped --config ./config/win_all.yml `
        --data-source-list "image.vmdk, folder with collection, surge.zip, velociraptor_collection.7z" `
        --local-storage x: `
        --in-link "https://myaccount.file.core.windows.net/myclient/?sp=rl&st=...VWjgWTY8uc%3D&sr=s" `
        --out-link "https://myaccount.file.core.windows.net/internal-cache/myclient/?sp=rcwl&st=2023-04-21T20...2FZWEA%3D&sr=s" `
        --start-date 2023-01-01 `
        --end-date 2023-02-01 `
        --ioc-file ./iocs.txt
```

## Parameters
<details>
    <summary>Click to show the parameters for `wiskess_rust.exe whipped`</summary>
    
    --config <String>
        Optional. The paths to the configuration file, i.e. ./config/win_all.yml
            
    --data-source-list <String>
        Required. The paths to the file, folder of images, collections, etc. Must be separated by comma ',' or new line

    --local-storage <String>
        Required. The path to where the data is temporarily downloaded to and Wiskess output is stored locally

    --in-link <String>
        Required. The link that the data is stored on, i.e.
        https://myaccount.file.core.windows.net/myclient/?sp=rl&st=...VWjgWTY8uc%3D&sr=s

    --out-link <String>
        Required. The link where you need the wiskess output uploaded to, i.e.
        https://myaccount.file.core.windows.net/results/myclient/?sp=rcwl&st=2023-04-21T20...2FZWEA%3D&sr=s

    --ioc-file <String>

    --start-date <String>
        Required. The start time from when we want to look for interesting information. Normally aligned with the incident timeframe.    
        Caution: specifying a wide timeframe will cause performance issues.

    --end-date <String>
        Required. The end time to when we want to look for interesting information. Normally aligned with the incident timeframe.        
        Caution: specifying a wide timeframe will cause performance issues.

    --update
        Optional. Set this flag to update the Wiskess results, such as changing the timeframe or after adding new IOCs to the list.      

    --keep-evidence
        Optional. Set this flag to keep the downloaded data on your local storage. Useful if wanting to process the data after Wiskess.  
        Caution: make sure you have enough disk space for all the data source list.
</details>
    
# WISKESS `wiskess_rust.exe wiskess`
This is the Rust version of WISKESS, which uses parallel processing of multiple processors, enriches the data and creates reports. It is invoked by the command `wiskess_rust.exe whipped`, but can also be used independently with the command `wiskess_rust.exe wiskess`.

## Usage
* Mount the image to a drive, i.e. using Arsenal Image Mounter. Can be skipped if using a folder of artefacts.
* Provide the file path to the artefacts. Such as the drive it has been mounted, being the drive letter it was originally located on. Or the file path to the folder it was extracted/downloaded to.
* Provide the output path, where you want to store collected artefacts and the results.
* Add your indicators to a file, you can call it iocs.txt and place it in the same folder as wiskess.ps1, or specify the location of your file with the flag -iocFile "path_to_your_iocs.txt"
* The script has a set of predefined locations of Windows artefacts, which it uses to pass to the right parser. If the artefact is not found at the default location, it will ask the user to enter the path to it.

## Parameters
<details>
    <summary>Click to show the parameters for `wiskess_rust.exe wiskess`</summary>
        
    --config <String>
        Optional. The paths to the configuration file. Default: ./config/main_win.yml
            
    --data-source <String>
        Required. The drive letter the image is mounted on, or the file path to the extracted collection.

    --out-path <String>
        Required. Where you want to store the analysis and artefact results.

    --ioc-file <String>
        Optional. The path to a file containing a list of indicators of compromise. Each indicator is on a separate line.

    --start-date <String>
        Optional. The start time from when we want to look for interesting information. Normally aligned with the incident timeframe.    
        Caution: specifying a high number of days will cause performance issues.

    --end-date <String>
        Optional. The end time to when we want to look for interesting information. Normally aligned with the incident timeframe.        
        Caution: specifying a high number of days will cause performance issues.

</details>

## Examples for wiskess
## EXAMPLE 1

Minimum arguments required to collect artefacts from E:, with a quick triage of the last 7 days and storing results to Z:\Project file path. And provide a list of indicators in a file path.
```
    ./wiskess_rust.exe wiskess --data-source E: -out-path "Z:\Project" --start-date 2023-01-01 --end-date 2023-02-01 --ioc-file ./iocs.txt

```
