Echo "Waiting...";
Start-Sleep -s 60;
Echo "Bar...";
Write-Error "error";
$host.SetShouldExit(1);
