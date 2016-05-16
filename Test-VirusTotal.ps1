#requires -Version 4 -Modules Pester
function Test-VirusTotal
{
<#
    .SYNOPSIS
        Tests a File for VirusTotal Positives
        
    .DESCRIPTION
        Gets the Hash of a file and uses the VirusTotal api to test for positives.
    
    .PARAMETER FilePath
        Path to the File to be tested.
    
    .PARAMETER ApiKey
        VirusTotal requires a Public or Private ApiKey to use it's api. You can signup for 
        an Apikey at the following url
            
            https://www.virustotal.com/en/#signup
          
    .EXAMPLE
        Test-VirusTotal -FilePath 'C:\TestProject\Files\adksetup.exe' -ApiKey $ApiKey
        
        Output:

        scans         : @{Bkav=; MicroWorld-eScan=; nProtect=; CMC=; CAT-QuickHeal=; ALYac=; Malwarebytes=; Zillya=; SUPERAntiSpyware=; K7AntiVirus=; BitDefender=; K7GW=; TheHacker=; Arcabit=; Baidu=; F-Prot=; Symantec=; ESET-NOD32=; 
                        TrendMicro-HouseCall=; Avast=; ClamAV=; Kaspersky=; Alibaba=; NANO-Antivirus=; AegisLab=; Tencent=; Ad-Aware=; Emsisoft=; Comodo=; F-Secure=; DrWeb=; VIPRE=; TrendMicro=; McAfee-GW-Edition=; Sophos=; Cyren=; 
                        Jiangmin=; Avira=; Antiy-AVL=; Kingsoft=; Microsoft=; ViRobot=; GData=; AhnLab-V3=; McAfee=; AVware=; VBA32=; Baidu-International=; Zoner=; Rising=; Yandex=; Ikarus=; Fortinet=; AVG=; Panda=; Qihoo-360=}
        scan_id       : b0f5cd130d9be84b6af2a5f3f4baaf0bfa261431d6f6605ff8c4f026d16d29eb-1463143831
        sha1          : bc3efa72e1bb9e9998b5f4d893701e4d2d92e597
        resource      : 760E0DCC3440756EBE1657DC43CA6EF1
        response_code : 1
        scan_date     : 2016-05-13 12:50:31
        permalink     : https://www.virustotal.com/file/b0f5cd130d9be84b6af2a5f3f4baaf0bfa261431d6f6605ff8c4f026d16d29eb/analysis/1463143831/
        verbose_msg   : Scan finished, information embedded
        total         : 56
        positives     : 0
        sha256        : b0f5cd130d9be84b6af2a5f3f4baaf0bfa261431d6f6605ff8c4f026d16d29eb
        md5           : 760e0dcc3440756ebe1657dc43ca6ef1


    .EXAMPLE
        Test-VirusTotal -FilePath 'C:\TestProject\Files\MicrosoftDeploymentToolkit2013_x64.msi' -ApiKey $ApiKey
        
        Output:

        scans         : @{Bkav=; MicroWorld-eScan=; nProtect=; CMC=; CAT-QuickHeal=; ALYac=; Malwarebytes=; Zillya=; AegisLab=; TheHacker=; BitDefender=; K7GW=; K7AntiVirus=; Arcabit=; Baidu=; F-Prot=; Symantec=; ESET-NOD32=; 
                        TrendMicro-HouseCall=; Avast=; ClamAV=; Kaspersky=; Alibaba=; NANO-Antivirus=; ViRobot=; Rising=; Ad-Aware=; Emsisoft=; Comodo=; F-Secure=; DrWeb=; VIPRE=; TrendMicro=; McAfee-GW-Edition=; Sophos=; Cyren=; 
                        Jiangmin=; Avira=; Antiy-AVL=; Kingsoft=; Microsoft=; SUPERAntiSpyware=; GData=; AhnLab-V3=; McAfee=; AVware=; VBA32=; Baidu-International=; Zoner=; Tencent=; Yandex=; Ikarus=; Fortinet=; AVG=; Panda=; Qihoo-360=}
        scan_id       : bc8df6ed7e92450dab746d6d7ef89129e3faab1a69354b5a3d30044178deddd8-1462207552
        sha1          : 65f7549f1568fcbd472f2e8bf28310ec6e16ecb9
        resource      : 97056770215365C84A5848D4FCE3105A
        response_code : 1
        scan_date     : 2016-05-02 16:45:52
        permalink     : https://www.virustotal.com/file/bc8df6ed7e92450dab746d6d7ef89129e3faab1a69354b5a3d30044178deddd8/analysis/1462207552/
        verbose_msg   : Scan finished, information embedded
        total         : 56
        positives     : 1
        sha256        : bc8df6ed7e92450dab746d6d7ef89129e3faab1a69354b5a3d30044178deddd8
        md5           : 97056770215365c84a5848d4fce3105a

    .EXAMPLE
        Test-VirusTotal -FilePath 'C:\TestProject\Files\DropboxInstaller.exe' -ApiKey $ApiKey
        
        Output:

        WARNING: E:\TestProject\Files\DropboxInstaller.exe: The requested resource is not among the finished, queued or pending scans
        
    .INPUTS
        System.String
        
    .OUTPUTS
        PSCustomObject
        
    .NOTES
        The VirusTotal Public Api has a Request limit of 4 requests per minute. If Testing more than 4
        files at a time, this function will sleep for 60 seconds if the Api request limit has been hit.
        If using this with Pester, this could slow your tests down considerably so plan accordingly.
        
        The current implementation Requires Powershell v4 or above. This may change if I write my own 
        replacement for Get-FileHash.
    
    .LINK
        https://github.com/gerane/PesterVirusTotal

    .LINK
        https://www.virustotal.com/en/#signup

#>
    [Cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$Apikey
    )
    
    Process
    {
        Write-Verbose -Message "File: $($FilePath)"
        
        if (! (Test-Path -Path $FilePath))
        {
            Throw "$($FilePath) does not Exist!"
        }
        
        $Hash = (Get-FileHash -Path $FilePath -Algorithm MD5).hash
        Write-Verbose -Message "Hash: $($Hash)"
        
        $Results = Invoke-RestMethod -Method Get -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{'resource' = $Hash; 'apikey' = $apikey}

        while (!$Results)
        {                
            Write-Verbose -Message "Hit VirusTotal Request Limit, Sleeping for 60 seconds."
            Start-Sleep -Seconds 60
            $Results = Invoke-RestMethod -Method Get -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{'resource' = $Hash; 'apikey' = $apikey}
        }
    
        $ResponseCode = $Results.response_code
        Write-Verbose -Message "Response Code: $($ResponseCode)"
    
        if ($ResponseCode -eq '0') 
        { 
            Write-Warning -Message "$($FilePath): $($Results.verbose_msg)"
        }
        elseif ($ResponseCode -eq '1')
        {        
            Write-Verbose -Message "Positive: $($Results.positives)"
            Return $Results
        }
        elseif ($ResponseCode -eq '-1')
        {
            Throw "Response Code was either Empty or not in expected range"
        }
    }
}
