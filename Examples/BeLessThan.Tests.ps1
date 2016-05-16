<#
    Example Output:

    Describing Validate Files with VirusTotal
      [+] Should have Less Than 1 Matches: adksetup.exe 522ms
    WARNING: C:\TestProject\Files\DropboxInstaller.exe: The requested resource is not among the finished, queued or pending scans
      [+] Should have Less Than 1 Matches: DropboxInstaller.exe 1.06s      
      [+] Should have Less Than 1 Matches: JavaAccessBridge.dll 466ms
      [-] Should have Less Than 1 Matches: MicrosoftDeploymentToolkit2013_x64.msi 60.8s
        Expected {1} to be less than {1}
        12:             $Results.positives | Should BeLessThan 1
        at <ScriptBlock>, C:\Github\PesterVirusTotal\Examples\BeLessThan.Tests.ps1: line 12
      [+] Should have Less Than 1 Matches: PSRunner.dll 130ms
      [+] Should have Less Than 1 Matches: UIAutomation.dll 426ms
#>

. "$PSScriptRoot\..\Test-VirusTotal.ps1"

$files = Get-ChildItem -Path "$PSScriptRoot\Files"

Describe 'Validate Files with VirusTotal' {
    
    foreach ($File in $Files)
    {                               
        It "Should have Less Than 1 Matches: $($File.Name)" {
            $Results = Test-VirusTotal -File $file.FullName -Apikey $apikey
            $Results.positives | Should BeLessThan 1
        }
    }
}

