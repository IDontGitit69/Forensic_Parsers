$logPath = "C:\Path\To\Your\EvtxFiles"

Get-ChildItem $logPath -Filter *.evtx | ForEach-Object {

    $file = $_.FullName
    Write-Host "Processing $file..."

    try {
        $events = Get-WinEvent -Path $file -ErrorAction Stop

        if ($events.Count -gt 0) {
            $first = $events | Sort-Object TimeCreated | Select-Object -First 1
            $last  = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1

            [PSCustomObject]@{
                FileName = $_.Name
                OldestEvent = $first.TimeCreated
                NewestEvent = $last.TimeCreated
            }
        }
        else {
            [PSCustomObject]@{
                FileName = $_.Name
                OldestEvent = "No events"
                NewestEvent = "No events"
            }
        }
    }
    catch {
        Write-Warning "Failed to read $file"
    }

} | Format-Table -AutoSize
