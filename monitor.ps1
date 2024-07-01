$folderPath = "Folder"
$scriptPath = "mail_notification.py"

$filter = '*.*'

$fsw = New-Object IO.FileSystemWatcher $folderPath, $filter
$fsw.EnableRaisingEvents = $true
$fsw.IncludeSubdirectories = $false

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    Write-Host "File ${changeType}: ${path}"
    # Ensure Python is correctly invoked with the script
    & python $scriptPath
}

Register-ObjectEvent $fsw 'Created' -Action $action

Write-Host "Monitoring folder: $folderPath"
while ($true) {
    Start-Sleep -Seconds 5
}
