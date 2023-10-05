# wiskess_rust

![271793948-27e9b4b3-0a7f-4efb-a844-2eda7a8a6385](https://github.com/vividDuck/wiskess_rust/assets/122105925/46cacffc-a0d0-4ec7-b1cb-60bca314d2bb)

WISKESS automates the Windows evidence processing for Incident Response investigations. Rust version is a program that has been developed with enhanced parallel processing and reliability.

This is the Rust version of WISKESS, which uses parallel processing of multiple tools including Hayabusa, Chainsaw, EZ-Tools, Loki, SCCM Recently Used, WMI Persistence, python-cim, Browsing History, Hindsight, ripgrep, velociraptor, and more can be added. 

It includes enrichment tools that scan the data source using your IOC list, yara rules, and open source intelligence. 

The results are structured into folders in CSV files that can be opened with text editors and searched across using tools like grep. The tool produces a report of the system info and files that have produced results in the Analysis folder.

The output is generated into reports of a timeline that is compatible with ingesting into visualisation tools including, timesketch, elastic and splunk.


# Whipped by WISKESS `whipped.ps1`
This script will pull data from an AWS or Azure store, process it with wiskess and upload the output to a store.

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
whipped.ps1 -dataSourceList "image.vmdk, folder with collection, surge.zip, velociraptor_collection.7z" `
        -local_storage x:
        -storageType azure
        -in_link "https://myaccount.file.core.windows.net/myclient/?sp=rl&st=...VWjgWTY8uc%3D&sr=s" `
        -out_link "https://myaccount.file.core.windows.net/internal-cache/myclient/?sp=rcwl&st=2023-04-21T20...2FZWEA%3D&sr=s" `
        -time_start 2023-01-01 `
        -time_end 2023-02-01
```

## Parameters
<details>
    <summary>Click to show the parameters for `whipped.ps1`</summary>
    -dataSourceList <String>
        Required. The paths to the file, folder of images, collections, etc. Must be separated by comma ','

    -local_storage <String>
        Required. The path to where the data is temporarily downloaded to and Wiskess output is stored locally

    -storageType <String>
        Requried. Either 'azure' or 'aws' - based on where the data source is stored.

    -in_link <String>
        Required. The link that the data is stored on, i.e.
        https://myaccount.file.core.windows.net/myclient/?sp=rl&st=...VWjgWTY8uc%3D&sr=s

    -out_link <String>
        Required. The link where you need the wiskess output uploaded to, i.e.
        https://myaccount.file.core.windows.net/results/myclient/?sp=rcwl&st=2023-04-21T20...2FZWEA%3D&sr=s

    -ioc_file <String>

    -time_start <String>
        Required. The start time from when we want to look for interesting information. Normally aligned with the incident timeframe.    
        Caution: specifying a wide timeframe will cause performance issues.

    -time_end <String>
        Required. The end time to when we want to look for interesting information. Normally aligned with the incident timeframe.        
        Caution: specifying a wide timeframe will cause performance issues.

    -update [<SwitchParameter>]
        Optional. Set this flag to update the Wiskess results, such as changing the timeframe or after adding new IOCs to the list.      

    -keepEvidence [<SwitchParameter>]
        Optional. Set this flag to keep the downloaded data on your local storage. Useful if wanting to process the data after Wiskess.  
        Caution: make sure you have enough disk space for all the data source list.

    -toolPath <String>
        Optional. The path to the directory of the whipped.ps1 script
</details>
    
# WISKESS `wiskess.ps1`
This is the PowerShell version of WISKESS, which uses parallel processing of multiple processors, enriches the data and creates reports. It is invoked by `whipped.ps1`, but can also be used independently.

## Requirements
run `setup.ps1` using PowerShell as Administrator

## Usage
* Mount the image to a drive, i.e. using Arsenal Image Mounter. Can be skipped if using a folder of artefacts.
* Provide the file path to the artefacts. Such as the drive it has been mounted, being the drive letter it was originally located on. Or the file path to the folder it was extracted/downloaded to.
* Provide the output path, where you want to store collected artefacts and the results.
* Add your indicators to a file, you can call it iocs.txt and place it in the same folder as wiskess.ps1, or specify the location of your file with the flag -iocFile "path_to_your_iocs.txt"
* The script has a set of predefined locations of Windows artefacts, which it uses to pass to the right parser. If the artefact is not found at the default location, it will ask the user to enter the path to it.

## Parameters
<details>
    <summary>Click to show the parameters for `wiskess.ps1`</summary>
    -dataSource <String>
        Required. The drive letter the image is mounted on.

    -outFilePath <String>
        Required. Where you want to store the analysis and artefact results.

    -iocFile <String>
        Optional. The path to a file containing a list of indicators of compromise. Each indicator is on a separate line.

    -time_start <String>
        Optional. The start time from when we want to look for interesting information. Normally aligned with the incident timeframe.    
        Caution: specifying a high number of days will cause performance issues.

    -time_end <String>
        Optional. The end time to when we want to look for interesting information. Normally aligned with the incident timeframe.        
        Caution: specifying a high number of days will cause performance issues.

    -noVelociraptor [<SwitchParameter>]
        Optional. Flag to skip the collection using Velociraptor to speed up analysis. Can cause access control issues if set.

    -clawsOut [<SwitchParameter>]
        Optional. Run an intense system-wide scan for IOCs using ripgrep and thor

    -wmiParse [<SwitchParameter>]
        Optional. Parse the WMI artefacts using WMI-CIM. Can cause performance issues.

    -noInput [<SwitchParameter>]
        Optional. Skip all actions needing a user input. Useful for batch processes or benchmarking.

    -collection [<SwitchParameter>]

    -toolPath <String>
        Optional. The path to the directory of the wiskess.ps1 script
</details>

## Examples for wiskess
## EXAMPLE 1

Minimum arguments required to collect artefacts from E:, with a quick triage of the last 7 days and storing results to Z:\Project file path.
```
    .\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-02-01

```
## EXAMPLE 2

Don't ask for any user input, just do it. Also only collect the minimum files and only look back the past 1 day. Useful for batch processes or benchmarking.
```
    .\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-01-02 -noInput -noVelociraptor

```
## EXAMPLE 3

Only collect the minimum files. Useful for saving disk space and time.
```
.\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-02-01 -noVelociraptor

```
## EXAMPLE 4

Run an intense scan of the artefacts. This includes processing of WMI with python-cim, full scans of the mounted drive using ripgrep with the iocs.txt list, and loki with all flags enabled
```
    .\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-02-01 -clawsOut

```
## EXAMPLE 5

Provide a list of indicators in a file path.
```
.\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-02-01 -iocFile "Z:\Project\iocs.txt"    
```

## EXAMPLE 6

Run the WMI parsing functions.
```
.\wiskess.ps1 -dataSource E: -outFilePath "Z:\Project" -time_start 2023-01-01 -time_end 2023-02-01 -wmiParse
```
