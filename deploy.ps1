Echo "Running post deployment tests...";

#hack to avoid certificate error
$x = @"
   using System.Net;
   using System.Security.Cryptography.X509Certificates;
   public class TrustAllCertsPolicy : ICertificatePolicy {
       public bool CheckValidationResult(
           ServicePoint srvPoint, X509Certificate certificate,
           WebRequest request, int certificateProblem) {
           return true;
       }
   }
"@;

add-type $x;

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;

#endpoint to hit
$uri = 'https://127.0.0.1:8987/';

#token for connector API
$token = $env:token;

#set header
$headers = @{
  "Authorization" = "Bearer $token"
};

#make call to connector API
try {
    if((invoke-RestMethod -Uri $uri -Headers $headers -Method Get) -eq "ok!") {
       Echo "Checked in with connector service okay...";
    } else {
       Echo "Unexpected response from connector service...";
    };
} catch {
    Echo "Error connecting to connector service...";
    Throw $_.exception.message;
}
