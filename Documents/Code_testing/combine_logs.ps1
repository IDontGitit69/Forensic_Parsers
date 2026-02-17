# PowerShell Script to Combine CSV-formatted .LOG files
# Usage: .\combine-logs.ps1 -SourceDir "C:\Path\To\Logs" -OutputFile "C:\Path\To\combined.log"

param(
    [Parameter(Mandatory=$false)]
    [string]$SourceDir = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "combined.log"
)

Write-Host "Combining .LOG files from: $SourceDir" -ForegroundColor Cyan
Write-Host "Output file: $OutputFile" -ForegroundColor Cyan

# Get all .LOG files in the directory
$logFiles = Get-ChildItem -Path $SourceDir -Filter "*.LOG" | Sort-Object Name

if ($logFiles.Count -eq 0) {
    Write-Host "No .LOG files found in $SourceDir" -ForegroundColor Red
    exit
}

Write-Host "Found $($logFiles.Count) .LOG files" -ForegroundColor Green

# Read the first file to get the header
$firstFile = $logFiles[0]
$header = Get-Content $firstFile.FullName -First 1

Write-Host "Using header from: $($firstFile.Name)" -ForegroundColor Yellow

# Create the output file with the header
$header | Out-File -FilePath $OutputFile -Encoding UTF8

$totalLines = 0

# Process each log file
foreach ($file in $logFiles) {
    Write-Host "Processing: $($file.Name)..." -ForegroundColor Gray
    
    # Read all lines except the header and append to output
    $lines = Get-Content $file.FullName | Select-Object -Skip 1
    $lineCount = $lines.Count
    $totalLines += $lineCount
    
    # Append to output file
    $lines | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    
    Write-Host "  Added $lineCount lines" -ForegroundColor DarkGray
}

Write-Host "`nDone! Combined $totalLines data lines from $($logFiles.Count) files" -ForegroundColor Green
Write-Host "Output saved to: $OutputFile" -ForegroundColor Cyan
