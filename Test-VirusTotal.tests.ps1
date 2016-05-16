. ($PSCommandPath -replace '\.tests\.ps1$', '.ps1')

function VirusTotalResults
{
    [Cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [int]$positives,
        
        [Parameter(Mandatory = $true)]
        [string]$response_code,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Missing', 'Success', 'Error')]
        [string]$verbose_msg
    )
    
    switch ($verbose_msg)
    {
        Missing { $new_verbose_msg = 'The requested resource is not among the finished, queued or pending scans' }
        Success { $new_verbose_msg = 'Scan finished, information embedded' }
        Error   { $new_verbose_msg = 'An Error Occurred' }
    }
    
    
    $MockedResults = @{
        positives = $positives;
        response_code = $response_code;
        verbose_msg = $new_verbose_msg
    }
    
    Return $MockedResults
}


Describe 'Test-VirusTotal' {
    $MockedHash = 'F79A8679643491D9863078AEA5C021B6'
    Mock Get-FileHash { Return @{ hash = $MockedHash } }
    Mock Test-Path { $true }
    
    Context 'File Hash Returns 0 Positives' {
        Mock Invoke-RestMethod { VirusTotalResults -positives 0 -response_code 1 -verbose_msg Success }
        
        It 'Runs without errors' {      
            $Results = { Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey' }
            $Results | Should Not Throw
        }
        
        It 'Returns 0 Positives' {      
            $Results = Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey'
            $Results.positives | Should Be 0
        }
    }
    
    Context 'File Hash Returns 3 Positives' {
        Mock Invoke-RestMethod { VirusTotalResults -positives 3 -response_code 1 -verbose_msg Success }      
        
        It 'Returns 3 Positives' {      
            $Results = Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey'
            $Results.positives | Should Be 3
        }
    }
    
    Context 'File Hash Returns 5 or Less Positives' {
        Mock Invoke-RestMethod { VirusTotalResults -positives 4 -response_code 1 -verbose_msg Success }
                
        It 'Returns 4 Positives' {      
            $Results = Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey'
            $Results.positives | Should BeLessThan 5
        }
    }
    
    Context 'VirusTotal has not seen this File Hash' {
        Mock Invoke-RestMethod { VirusTotalResults -positives 0 -response_code 0 -verbose_msg Missing }
        $Results = Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey'
        
        It 'Returns Missing Verbose Message ' {                  
            $Results.verbose_msg | Should Not Be 'The requested resource is not among the finished, queued or pending scans'
        }
        
        It 'Returns Null' {                  
            $Results.positives | Should BeNullOrEmpty
        }
    }
    
    Context 'Error Occurs' {
        Mock Invoke-RestMethod { VirusTotalResults -positives 0 -response_code -1 -verbose_msg Error }        
        
        It 'Returns Error Verbose Message ' {
            $Results = { Test-VirusTotal -FilePath "C:\FakePath.exe" -Apikey 'FakeApiKey' }
            $Results | Should Throw
        }
    }
}
