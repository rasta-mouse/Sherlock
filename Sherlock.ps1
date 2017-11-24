#
#
#    File: Sherlock.ps1
#    Author: @_RastaMouse
#    License: GNU General Public License v3.0#
#
# 

$Global:ExploitTable = $null

function Get-FileVersionInfo ($FilePath) {

    # Double slash for CIM_DataFile
    $FilePath = $FilePath.Replace("\", "\\")
    
    # PsH v1/v2 support via CIM_DataFile
    $VersionInfo = (Get-WmiObject -Class CIM_DataFile -Filter "Name='$FilePath'" | Select-Object Version).Version
    If( $VersionInfo ) {

    return $VersionInfo
    
    } else {
    
    # veery ugly hack, just works lol
    return '0.0.0000.0 (nada.0-0)'
    
    } 
 
}

function Get-InstalledSoftware($SoftwareName) {
    
    # Grab the PowerShell version
    $PshVersion = $host.version.Major

    # If version is less or equal to 2, can not support Win32_Product Class then return false
    if($PshVersion -le '2') {

    return $false 
    
    } Else { 
    
    $SoftwareVersion = Get-WmiObject -Class Win32_Product | Where { $_.Name -eq $SoftwareName } | Select-Object Version
    
        if ( $SoftwareVersion) {
        
        $SoftwareVersion = $SoftwareVersion.Version  # I have no idea what I'm doing
        
        return $SoftwareVersion
        
        } else { 
        
        return $false
        
        }
    }

}

function Get-Architecture {

    # This is the CPU architecture.  Returns "64-bit" or "32-bit".
    $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

    # This is the process architecture, e.g. are we an x86 process running on a 64-bit system.  Retuns "AMD64" or "x86".
    $ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE

    return $CPUArchitecture, $ProcessArchitecture

}

function Get-Cores {
    $cpu = Get-WmiObject -Class Win32_processor 
    $cores = Select-Object -InputObject $cpu -ExpandProperty NumberofCores

    return $cores
}

function New-ExploitTable {

    # Create the table
    $Global:ExploitTable = New-Object System.Data.DataTable

    # Create the columns
    $Global:ExploitTable.Columns.Add("Title")
    $Global:ExploitTable.Columns.Add("MSBulletin")
    $Global:ExploitTable.Columns.Add("CVEID")
    $Global:ExploitTable.Columns.Add("Link")
    $Global:ExploitTable.Columns.Add("VulnStatus")

    # Add the exploits we are interested in.

    # MS10
    $Global:ExploitTable.Rows.Add("User Mode to Ring (KiTrap0D)","MS10-015","2010-0232","https://www.exploit-db.com/exploits/11199/")
    $Global:ExploitTable.Rows.Add("Task Scheduler .XML","MS10-092","2010-3338, 2010-3888","https://www.exploit-db.com/exploits/19930/")
    # MS11
    $Global:ExploitTable.Rows.Add("AFD.sys Elevation of Privilege","MS11-046","2011-1249","https://www.exploit-db.com/exploits/40564/")
    $Global:ExploitTable.Rows.Add("AFD.sys Elevation of Privilege","MS11-080","2011-2005","https://www.exploit-db.com/exploits/18176/")
    # MS13
    $Global:ExploitTable.Rows.Add("NTUserMessageCall Win32k Kernel Pool Overflow","MS13-053","2013-1300","https://www.exploit-db.com/exploits/33213/")
    $Global:ExploitTable.Rows.Add("TrackPopupMenuEx Win32k NULL Page","MS13-081","2013-3881","https://www.exploit-db.com/exploits/31576/")
    # MS14
    $Global:ExploitTable.Rows.Add("ndproxy.sys Local Privilege Escalation","MS14-002","2013-5065","https://www.exploit-db.com/exploits/30014/")
    $Global:ExploitTable.Rows.Add("TrackPopupMenu Win32k Null Pointer Dereference","MS14-058","2014-4113","https://www.exploit-db.com/exploits/35101/")
    # MS15
    $Global:ExploitTable.Rows.Add("ClientCopyImage Win32k","MS15-051","2015-1701, 2015-2433","https://www.exploit-db.com/exploits/37367/")
    $Global:ExploitTable.Rows.Add("Font Driver Buffer Overflow","MS15-078","2015-2426, 2015-2433","https://www.exploit-db.com/exploits/38222/")
    # MS16
    $Global:ExploitTable.Rows.Add("'mrxdav.sys' WebDAV","MS16-016","2016-0051","https://www.exploit-db.com/exploits/40085/")
    $Global:ExploitTable.Rows.Add("Secondary Logon Handle","MS16-032","2016-0099","https://www.exploit-db.com/exploits/39719/")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privilege","MS16-135","2016-7255","https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135")
    # Miscs that aren't MS
    $Global:ExploitTable.Rows.Add("LNK Remote Code Execution Vulnerability","N/A","2017-8464","http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8464")
    $Global:ExploitTable.Rows.Add("Nessus Agent 6.6.2 - 6.10.3","N/A","2017-7199","https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html")

}

function Set-ExploitTable ($MSBulletin, $VulnStatus) {

    if ( $MSBulletin -like "MS*" ) {

        $Global:ExploitTable | Where { $_.MSBulletin -eq $MSBulletin

        } | ForEach-Object {

            $_.VulnStatus = $VulnStatus

        }

    } else {


    $Global:ExploitTable | Where { $_.CVEID -eq $MSBulletin

        } | ForEach-Object {

            $_.VulnStatus = $VulnStatus

        }

    }

}

function Get-Results {

    $Global:ExploitTable

}

function Find-AllVulns {

    if ( !$Global:ExploitTable ) {

        $null = New-ExploitTable
    
    }

        Find-MS10015
        Find-MS10092
        Find-MS11046
        Find-MS11080
        Find-MS13053
        Find-MS13081
        Find-MS14002
        Find-MS14058
        Find-MS15051
        Find-MS15078
        Find-MS16016
        Find-MS16032
        Find-MS16135
        Find-CVE20178464
        Find-CVE20177199

        Get-Results

}

function Find-MS10015 {

    $MSBulletin = "MS10-015"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\ntoskrnl.exe"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20591" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS10092 {

    $MSBulletin = "MS10-092"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\schedsvc.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\schedsvc.dll"

    } ElseIf ( $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20830" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS11046 {

    $MSBulletin = "MS11-046"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

    $Path = $env:windir + "\system32\drivers\afd.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".") 

    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            2600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "6081" ] } # WinXP SP3
            3790 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "3959" ] } # Win2k3 SP1
            6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18005" ] } # Win2k8 SP2
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21712" ] } # Win7 SP1
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS11080 {

    $MSBulletin = "MS11-080"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

    $Path = $env:windir + "\system32\drivers\afd.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".") 

    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            2600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt "6142" ] }
            3790 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt "4898" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}
function Find-MS13053 {

    $MSBulletin = "MS13-053"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]
                
        #Write-Host($Revision)

        switch ( $Build ) {

            2600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "5512" ] }
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "17000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22348" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20732" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS13081 {

    $MSBulletin = "MS13-081"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22435" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20807" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS14002 {

    $MSBulletin = "MS14-002"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

    $Path = $env:windir + "\system32\drivers\ndproxy.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".") 

    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            2600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "5512" ] } # WinXP SP3
            3790 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -eq "4573" ] } # Win2k3 SP2
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS14058 {

    $MSBulletin = "MS14-058"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    } ElseIf ( $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    }
     
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS15051 {

    $MSBulletin = "MS15-051"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    } ElseIf ( $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS15078 {

    $MSBulletin = "MS15-078"

    $Path = $env:windir + "\system32\atmfd.dll"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(" ")

    $Revision = $VersionInfo[2]

    switch ( $Revision ) {

        243 { $VulnStatus = "Appears Vulnerable" }
        default { $VulnStatus = "Not Vulnerable" }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16016 {

    $MSBulletin = "MS16-016"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\drivers\mrxdav.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "23317" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21738" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18189" ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16683" ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "103" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16032 {

    $MSBulletin = "MS16-032"
    $Architecture = Get-Architecture
    $Cores = Get-Cores

    If ($cores -lt 2) {

        $VulnStatus = "Not supported on single-core systems"      
    }

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\seclogon.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\seclogon.dll"

    } ElseIf ( $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\system32\seclogon.dll"

    } 

        $VersionInfo = Get-FileVersionInfo($Path)

        $VersionInfo = $VersionInfo.Split(".")

        $Build = [int]$VersionInfo[2]
        $Revision = [int]$VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19598 -Or ( $Revision -ge 23000 -And $Revision -le 23909 ) ] }
            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16000 ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19148 -Or ( $Revision -ge 23000 -And $Revision -le 23347 ) ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17649 -Or ( $Revision -ge 21000 -And $Revision -le 21767 ) ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18230 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 16724 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 161 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-CVE20178464 {

    $CVEID = "2017-8464"

    $Path = $env:windir + "\system32\shell32.dll"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
        
    $Build = [int]$VersionInfo[2]
    $Revision = [int]$VersionInfo[3].Split(" ")[0]

         switch ( $Build ) {
            2900 { $VulnStatus = "Not Vulnerable" }
            6000 { $VulnStatus = "Appears Vulnerable" }
            6001 { $VulnStatus = "Appears Vulnerable" }
            6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 24102 ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23806 ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 20604 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 18692 ] }
            10240 {$VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 17443 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 962 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 1356 ] }
            15063 {$VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 413 ] }
            default { $VulnStatus = "Unknown" }
            }
  
    Set-ExploitTable $CVEID $VulnStatus

}


function Find-CVE20177199 {

    $CVEID = "2017-7199"
    $SoftwareVersion = Get-InstalledSoftware "Nessus Agent"
    
    if ( !$SoftwareVersion ) {

        $VulnStatus = "Not Vulnerable"

    } else {

        $SoftwareVersion = $SoftwareVersion.Split(".")

        $Major = [int]$SoftwareVersion[0]
        $Minor = [int]$SoftwareVersion[1]
        $Build = [int]$SoftwareVersion[2]

        switch( $Major ) {

        6 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Minor -eq 10 -and $Build -le 3 -Or ( $Minor -eq 6 -and $Build -le 2 ) -Or ( $Minor -le 9 -and $Minor -ge 7 ) ] } # 6.6.2 - 6.10.3
        default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $CVEID $VulnStatus

}

function Find-MS16135 {

    $MSBulletin = "MS16-135"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    } ElseIf ( $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")
        
        $Build = [int]$VersionInfo[2]
        $Revision = [int]$VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23584 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18524 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16384 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}