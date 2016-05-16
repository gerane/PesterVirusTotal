# Pester and VirusTotal
The initial idea behind this was to use Pester to validate files in your Deployment Pipeline, but this can easily be expanded in many directions.

## VirusTotal ApiKey
VirusTotal requires a Public or Private ApiKey to use it's api. You can signup for an Apikey at the following url: [VirusTotal Signup](https://www.virustotal.com/en/#signup)

In this release it is up to the user to define and store their ApiKey. Carlos Perez also has a great module called [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal) for interacting with the VirusTotal Api that can also be used for Pester. Just be sure to account for the Api Request limits for your ApiKey.

## Example

In this Example, we can see several of the types of outcomes. 

``` powershell
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
```

The Output: 

![Eample Output](/Examples/ExampleOutput.png)

From the Output we can see the following:
* The WARNING will be shown if a File was not found in VirusTotal. This could be customized for different usecases. I may add a sitch to allow these to be terminating errors.
* The Failure occurred because there was 1 or more Positives on the 4th file tested.

This is just one example of how to run Pester tests. You may want to raise the Positive count to deal with false positives. This might change on a project to project or file to file basis.
