Echo "Starting...";

cd C:\appveyor\projects\wol-rst\applications\wol\;
Echo $pwd;

Import-Module -Name .\Tunable-SSL-Validator\TunableSSLValidator.psm1;
