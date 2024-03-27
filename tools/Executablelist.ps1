param(
    [Parameter(Mandatory=$true)]
    [string]$BasePath,

    [Parameter(Mandatory=$true)]
    [string]$AdditionalParam
)

# Define an array of input files and their respective columns
$filesAndColumns = @(
    @{Path="$BasePath\FileExecution\appcompatcache.csv"; Column='path'},
    @{Path="$BasePath\FileExecution\prefetch.csv"; Column='ExecutableName'},
    @{Path="$BasePath\FileExecution\*_Amcache_UnassociatedFileEntries.csv"; Column='Fullpath'},
    @{Path="$BasePath\FileExecution\*_Amcache_AssociatedFileEntries.csv"; Column='Fullpath'},
    @{Path="$BasePath\Registry\*\reg-User_UserAssist.csv"; Column='programname'}
    @{Path="$BasePath\Registry\*\reg-System_BamDam.csv"; Column='program'}
)

$outputCsv = "$BasePath\FileExecution\MISP.csv"

$results = @()

# Iterate through each file and extract the required data
foreach ($file in $filesAndColumns) {
    $data = Import-Csv -Path $file.Path

    $data | ForEach-Object {
        $lastPart = ($_.$($file.Column) -split '\\')[-1]

        # Only add to results if not already there
        if ($results -notcontains $lastPart) {
            $results += $lastPart
        }
    }
}

# Convert the results to a CSV-friendly format
$csvResults = $results | Sort-Object | ForEach-Object {
    [PSCustomObject]@{
        'path' = $_
    }
}

# Check and create the directory if it doesn't exist
if (-not (Test-Path (Split-Path $outputCsv -Parent))) {
    New-Item -Path (Split-Path $outputCsv -Parent) -ItemType Directory -Force
}

# Export the results to a CSV file
$csvResults | Export-Csv -Path $outputCsv -NoTypeInformation

# Remove the double quotes and trim whitespace, then filter out empty lines
(Get-Content $outputCsv) | ForEach-Object { $_ -replace '"', '' } | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() } | Set-Content $outputCsv

# Construct the command to be run with two parameters
$command = "py $AdditionalParam\MISPAPI.py '$BasePath\FileExecution' '$AdditionalParam'"

# Execute the command
Invoke-Expression $command

Write-Output "Script execution complete."
