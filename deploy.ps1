Echo "Starting...";

Start-Service -Name 'TestService';

add-type -Path $env:APPLICATION_PATH\disableCertValidate.dll;
