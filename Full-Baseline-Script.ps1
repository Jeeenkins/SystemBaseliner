
# [System level baselining]
#
# This script will gather the following details as a baseline of the system its run on...
#
# [Files]
#	- Make list of all exe's and hashes (file name, file location, hash and creation time) - Function Hunt-GetFiles-Exe 
#	- Make list of all cmd's and hashes (file name, file location, hash and creation time) - Function Hunt-GetFiles-Cmd 
#	- Make list of all bat's and hashes (file name, file location, hash and creation time) - Function Hunt-GetFiles-Bat 
#	- Make list of all DLL's and hashes (file name, file location, hash and creation time) - Function Hunt-GetFiles-DLL 
#	- Make list of all .ps1 files  (file name, file location, hash and creation time) - Function Hunt-GetFiles-PS1
#	- Make list of all alternate data streams (file name, file location, hash and creation time) - Function Hunt-GetFiles-ADS
#	- Make list of all driver files and hashes (file name, file location, hash and creation time) - Function Hunt-GetFiles-Drivers
#
#
# [Network]
#	- Make list of netstat in systems running state  -  Hunt-Network-NetStat
#	- Make list of local host file entries   -   Hunt-Network-HostFile
#	- Make list of firewall exclusions  -  Hunt-Network-EnabledFWRules
#	- Make list of all mapped drives  -  Hunt-Network-MappedDrives
#	

#
# [Startup]
#	- Make list of all auto-start registry keys  -   Hunt-Startup-Registry
#   - Make list of all scheduled tasks and their details  -  Hunt-Startup-SchedTasks
#	- Make list of all services and their details  -  Hunt-Startup-Services
#	- Make list of all Startup files  -   Hunt-Startup-StartFolder
#	
#
# [Accounts] 
#	- Make list of all local user accounts  -  Hunt-Accounts-LocalUsers
#   - Make list of all local groups and members
#
#



#########################################
# ------ Startup clean functions ------ #
#########################################

#if folder exists, remove then re-create clean directory
If (Test-Path $tempDir){Remove-Item $tempDir -Recurse}
New-Item -ItemType Directory -Path $tempDir



#########################################
# -------- Helper Sub-functions ------- #
#########################################

# [Sub function for Hunt-Startup-SchedTasks]
function Get-GroupMember {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Group')]
        [string[]]
            $LocalGroup,
        [Alias('CN','Computer')]
        [string[]]
            $ComputerName = '.'
    )

    foreach ($Computer in $ComputerName) {
        Write-Verbose "Checking membership of localgroup: '$LocalGroup' on $Computer"
	    try {
            foreach ($Group in $LocalGroup) {
                ([adsi]"WinNT://$Computer/$Group,group").psbase.Invoke('Members') | ForEach-Object {
                    New-Object -TypeName PSCustomObject -Property @{
                        ComputerName = $Computer
                        LocalGroup   = $Group
                        Member       = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
                    }
                }
                Write-Verbose "Successfully checked membership of local group: '$LocalGroup' on $Computer"
            }
	    } catch {
		    Write-Warning $_
	    }
    }	
}


# [Sub function for Hunt-Startup-SchedTasks]
function getSchedTasks($path) {
    $out = @()

    # Get root tasks
    $schedule.GetFolder($path).getSchedTasks(0) | % {
        $xml = [xml]$_.xml
        $out += New-Object psobject -Property @{
            "Name" = $_.Name
            "Path" = $_.Path
            "LastRunTime" = $_.LastRunTime
            "NextRunTime" = $_.NextRunTime
            "Actions" = ($xml.Task.Actions.Exec | % { "$($_.Command) $($_.Arguments)" }) -join "`n"
        }
    }

    # Get tasks from subfolders
    $schedule.GetFolder($path).GetFolders(0) | % {
        $out += getSchedTasks($_.Path)
    }

    #Output
    $out
}


# [Sub function for Hunt-Network-Netstat]
function Get-NetworkStatistics {
 
	[OutputType('System.Management.Automation.PSObject')]
	[CmdletBinding()]
	param(
		
		[Parameter(Position=0)]
		[System.String]$ProcessName='*',
		
		[Parameter(Position=1)]
		[System.String]$Address='*',		
		
		[Parameter(Position=2)]
		$Port='*',

		[Parameter(Position=3,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName=$env:COMPUTERNAME,

		[ValidateSet('*','tcp','udp')]
		[System.String]$Protocol='*',

		[ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
		[System.String]$State='*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*','IPv4','IPv6')]
        [string]$AddressFamily = '*'
	)
    
	begin{
        #Define properties
            $properties = 'ComputerName','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

        #store hostnames in array for quick lookup
            $dnsCache = @{}
            
	}
	
	process{

        foreach($Computer in $ComputerName) {

            #Collect processes
            if($ShowProcessNames){
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | select name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
                if($Computer -ne $env:COMPUTERNAME){

                    #define command
                        [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                    #define remote file path - computername, drive, folder path
                        $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                    #delete previous results
                        Try{
                            $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                        }
                        Catch{
                            Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                        }

                    #run command
                        Try{
                            $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                        }
                        Catch{
                            #If we didn't run netstat, break everything off
                            Throw $_
                            Break
                        }

                    #wait for process to complete
                        while (
                            #This while should return true until the process completes
                                $(
                                    try{
                                        get-process -id $processid -computername $Computer -ErrorAction Stop
                                    }
                                    catch{
                                        $FALSE
                                    }
                                )
                        ) {
                            start-sleep -seconds 2 
                        }
            
                    #gather results
                        if(test-path $remoteTempFile){
                    
                            Try {
                                $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                            }
                            Catch {
                                Throw "Could not get content from $remoteTempFile for results"
                                Break
                            }

                            Remove-Item $remoteTempFile -force

                        }
                        else{
                            Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                            Break
                        }
                }
                else{
                    #gather results on local PC
                        $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
                }

            #initialize counter for progress
                $totalCount = $results.count
                $count = 0
    
            #Loop through each line of results    
	            foreach($result in $results) {
            
    	            $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    
    	            if($item[1] -notmatch '^\[::'){
                    
                        #parse the netstat line for local address and port
    	                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $localAddress = $la.IPAddressToString
    	                        $localPort = $item[1].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $localAddress = $item[1].split(':')[0]
    	                        $localPort = $item[1].split(':')[-1]
    	                    }
                    
                        #parse the netstat line for remote address and port
    	                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $remoteAddress = $ra.IPAddressToString
    	                        $remotePort = $item[2].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $remoteAddress = $item[2].split(':')[0]
    	                        $remotePort = $item[2].split(':')[-1]
    	                    }

                        #Filter IPv4/IPv6 if specified
                            if($AddressFamily -ne "*")
                            {
                                if($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' )
                                {
                                    #Both are IPv6, or ipv6 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                                elseif($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) )
                                {
                                    #Both are IPv4, or ipv4 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                            }
    	    		
                        #parse the netstat line for other properties
    	    		        $procId = $item[-1]
    	    		        $proto = $item[0]
    	    		        $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	

                        #Filter the object
		    		        if($remotePort -notlike $Port -and $localPort -notlike $Port){
                                write-verbose "remote $Remoteport local $localport port $port"
                                Write-Verbose "Filtered by Port:`n$result"
                                continue
		    		        }

		    		        if($remoteAddress -notlike $Address -and $localAddress -notlike $Address){
                                Write-Verbose "Filtered by Address:`n$result"
                                continue
		    		        }
    	    			     
    	    			    if($status -notlike $State){
                                Write-Verbose "Filtered by State:`n$result"
                                continue
		    		        }

    	    			    if($proto -notlike $Protocol){
                                Write-Verbose "Filtered by Protocol:`n$result"
                                continue
		    		        }
                   
                        #Display progress bar prior to getting process name or host name
                            Write-Progress  -Activity "Resolving host and process names"`
                                -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                                -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                        #If we are running showprocessnames, get the matching name
                            if($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName'){
                        
                                #handle case where process spun up in the time between running get-process and running netstat
                                if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
                                else {$procName = "Unknown"}

                            }
                            else{$procName = "NA"}

		    		        if($procName -notlike $ProcessName){
                                Write-Verbose "Filtered by ProcessName:`n$result"
                                continue
		    		        }
    	    						
                        #if the showhostnames switch is specified, try to map IP to hostname
                            if($showHostnames){
                                $tmpAddress = $null
                                try{
                                    if($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0"){
                                        $remoteAddress = $Computer
                                    }
                                    elseif($remoteAddress -match "\w"){
                                        
                                        #check with dns cache first
                                            if ($dnsCache.containskey( $remoteAddress)) {
                                                $remoteAddress = $dnsCache[$remoteAddress]
                                                write-verbose "using cached REMOTE '$remoteAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $remoteAddress
                                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                            }
                                    }
                                }
                                catch{ }

                                try{

                                    if($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0"){
                                        $localAddress = $Computer
                                    }
                                    elseif($localAddress -match "\w"){
                                        #check with dns cache first
                                            if($dnsCache.containskey($localAddress)){
                                                $localAddress = $dnsCache[$localAddress]
                                                write-verbose "using cached LOCAL '$localAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $localAddress
                                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                                    $dnsCache.add($localAddress, $tmpAddress)
                                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                            }
                                    }
                                }
                                catch{ }
                            }
    
    	    		    #Write the object	
    	    		        New-Object -TypeName PSObject -Property @{
		    		            ComputerName = $Computer
                                PID = $procId
		    		            ProcessName = $procName
		    		            Protocol = $proto
		    		            LocalAddress = $localAddress
		    		            LocalPort = $localPort
		    		            RemoteAddress =$remoteAddress
		    		            RemotePort = $remotePort
		    		            State = $status
		    	            } | Select-Object -Property $properties								

                        #Increment the progress counter
                            $count++
                    }
                }
        }
    }
}






#########################################
# ----------- File Functions ---------- #
#########################################

# Get file name, file location, hash and creation time of all executable files
Function Hunt-GetFiles-Exe () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $allexes = Get-ChildItem -Path $drives -Include "*.exe" -Recurse -ErrorAction SilentlyContinue
    $outfile = "$tempDir\$hostname-$timestamp-EXE.csv"

    foreach ($exe in $allexes) {
        $filename = $exe.Name
        $fullfilename = $exe.FullName
        $hash =(Get-FileHash -Path $fullfilename -Algorithm sha256).hash
        write-output "$hostname,$filename,$fullfilename,$hash,$timestamp" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}


Function Hunt-GetFiles-Cmd () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $allcmds = Get-ChildItem -Path $drives -Include "*.cmd" -Recurse -ErrorAction SilentlyContinue
    $outfile = "$tempDir\$hostname-$timestamp-CMD.csv"

    foreach ($cmd in $allcmds) {
        $filename = $cmd.Name
        $fullfilename = $cmd.FullName
        $hash =(Get-FileHash -Path $fullfilename -Algorithm sha256).hash
        write-output "$hostname,$filename,$fullfilename,$hash,$timestamp" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}



Function Hunt-GetFiles-Bat () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $allbats = Get-ChildItem -Path $drives -Include "*.bat" -Recurse -ErrorAction SilentlyContinue
    $outfile = "$tempDir\$hostname-$timestamp-BAT.csv"

    foreach ($bat in $allbats) {
        $filename = $bat.Name
        $fullfilename = $bat.FullName
        $hash =(Get-FileHash -Path $fullfilename -Algorithm sha256).hash
        write-output "$hostname,$filename,$fullfilename,$hash,$timestamp" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}




Function Hunt-GetFiles-DLL () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $alldlls = Get-ChildItem -Path $drives -Include "*.dll" -Recurse -ErrorAction SilentlyContinue
    $outfile = "$tempDir\$hostname-$timestamp-DLL.csv"

    foreach ($dll in $alldlls) {
        $filename = $dll.Name
        $fullfilename = $dll.FullName
        $hash =(Get-FileHash -Path $fullfilename -Algorithm sha256).hash
        write-output "$hostname,$filename,$fullfilename,$hash,$timestamp" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}


Function Hunt-GetFiles-PS1 () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $allps1 = Get-ChildItem -Path $drives -Include "*.ps1" -Recurse -ErrorAction SilentlyContinue
    $outfile = "$tempDir\$hostname-$timestamp-PS1.csv"

    foreach ($ps1 in $allps1) {
        $filename = $ps1.Name
        $fullfilename = $ps1.FullName
        $hash =(Get-FileHash -Path $fullfilename -Algorithm sha256).hash
        write-output "$hostname,$filename,$fullfilename,$hash,$timestamp" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}



Function Hunt-GetFiles-ADS () {

    $drives = (get-wmiobject win32_volume | ? { $_.DriveType -eq 3 } | % { get-psdrive $_.DriveLetter[0] }).root
    $AllAltDS = get-childitem -path $drives -recurse -ErrorAction SilentlyContinue | % { get-item $_.FullName -stream * } | where stream -ne ':$Data' | where stream -ne 'Zone.Identifier'
    $outfile = "$tempDir\$hostname-$timestamp-ADS.csv"

    foreach ($AltDS in $AllAltDS) {
        $FileName = $AltDS.FileName
        $PSChildName = $AltDS.PSChildName
        $Stream = $AltDS.Stream
        Write-Output "$hostname,$FileName,$PSChildName,$Stream" | Out-File -FilePath $outfile -Append -Encoding ASCII
    }
}



Function Hunt-GetFiles-Drivers () {

#C:\Windows\System32\DriverStore


}




#########################################
# ---------- Network Functions -------- #
#########################################

function Hunt-Network-NetStat () {

    $outfile = "$tempDir\$hostname-$timestamp-NetStat.csv"
    $AllConnections = Get-NetworkStatistics

    foreach ($connection in $AllConnections) {
        $Protocol = $connection.Protocol
        $LocalAddress = $connection.LocalAddress
        $LocalPort = $connection.LocalPort
        $RemoteAddress = $connection.RemoteAddress
        $RemotePort = $connection.RemotePort
        $State = $connection.State
        $ProcessName = $connection.ProcessName
        $ProcID = $connection.PID
        Write-Output "$hostname,$Protocol,$LocalAddress,$LocalPort,$RemoteAddress,$RemotePort,$State,$ProcessName,$ProcID" | Out-File -FilePath $outfile -Append -Encoding ASCII
     }
}



function Hunt-Network-HostFile () {
    $outfile = "$tempDir\$hostname-$timestamp-HostFile.csv"
    $Pattern = '^(?<IP>\d{1,3}(\.\d{1,3}){3})\s+(?<Host>.+)$'
    $File    = "$env:SystemDrive\Windows\System32\Drivers\etc\hosts"
    $Entries = @()
    (Get-Content -Path $File)  | ForEach-Object { If ($_ -match $Pattern) {$Entries += "$hostname,$($Matches.IP),$($Matches.Host)"   } }
    $Entries | Out-File -FilePath $outfile -Encoding ASCII
}



function Hunt-Network-EnabledFWRules () {

    $outfile = "$tempDir\$hostname-$timestamp-EnabledFWRules.csv"
    $EnabledFWRules = (New-object –comObject HNetCfg.FwPolicy2).rules | where-object {$_.Enabled -eq $True}

    foreach ($Rule in $EnabledFWRules) {
        $Name = $Rule.Name                 
        $Description = $Rule.Description              
        $ApplicationName = $Rule.ApplicationName     
        $serviceName = $Rule.serviceName             
        $Protocol = $Rule.Protocol               
        $LocalPorts = $Rule.LocalPorts              
        $RemotePorts = $Rule.RemotePorts            
        $LocalAddresses = $Rule.LocalAddresses         
        $RemoteAddresses = $Rule.RemoteAddresses        
        $IcmpTypesAndCodes = $Rule.IcmpTypesAndCodes       
        $Direction = $Rule.Direction            
        $Interfaces = $Rule.Interfaces             
        $InterfaceTypes  = $Rule.InterfaceTypes        
        $Enabled  = $Rule.Enabled               
        $Grouping = $Rule.Grouping              
        $Profiles   = $Rule.Profiles             
        $EdgeTraversal   = $Rule.EdgeTraversal        
        $Action = $Rule.Action                 
        $EdgeTraversalOptions = $Rule.EdgeTraversalOptions   
        Write-Output "$hostname,$Name,$Description,$ApplicationName,$serviceName,$Protocol,$LocalPorts,$RemotePorts,$LocalAddresses,$RemoteAddresses,$IcmpTypesAndCodes,$Direction,$Interfaces,$InterfaceTypes,$Enabled,$Grouping,$Profiles,$EdgeTraversal,$Action,$EdgeTraversalOptions" | Out-File -FilePath $outfile -Append -Encoding ASCII
    }
}



function Hunt-Network-MappedDrives () {
    
    $outfile = "$tempDir\$hostname-$timestamp-MappedDrives.csv"
    $MappedDrives = Get-WmiObject -Class Win32_MappedLogicalDisk | select Name, ProviderName

    Foreach ($Drive in $MappedDrives) {
        $DriveName = $Drive.Name
        $ProviderName  = $Drive.ProviderName 
       Write-Output "$hostname,$DriveName,$ProviderName" | Out-File -FilePath $outfile -Append -Encoding ASCII
     }
}




#########################################
# --------- Startup Functions --------- #
#########################################

function Hunt-Startup-SchedTasks () {

    $outfile = "$tempDir\$hostname-$timestamp-SchedTasks.csv"
    $schtasks = schtasks /query /fo csv /v | convertfrom-csv 

    foreach ($task in $schtasks) {

        $TaskName = $task.TaskName
        $TaskToRun = $task.'Task To Run'
        $NextRun = $task.'Next Run Time'
        $Author = $task.Author
        $LastRunTime = $task.'Last Run Time'
        $ScheduleType = $task.'Schedule Type'
        $LogonMode = $task.'Logon Mode'
        $RunAsUser = $task.'Run As User'
        $ScheduledState = $task.'Scheduled Task State'

        $string = "$hostname,$TaskName,$TaskToRun,$NextRun,$Author,$LastRunTime,$ScheduleType,$LogonMode,$RunAsUser,$ScheduledState"

        if ($string -ne "TaskName,Task To Run,Next Run Time,Author,Last Run Time,Schedule Type,Logon Mode,Run As User,Scheduled Task State") {write-output $string | Out-File -FilePath $outfile -Append -Encoding ASCII}
     }
}




Function Hunt-Startup-Services () {

    $allservices = Get-WmiObject win32_service | Select * | Sort State, Name
    $outfile = "$tempDir\$hostname-$timestamp-Services.csv"

    foreach ($service in $allservices) {
        $Name = $service.Name
        $DisplayName = $service.DisplayName
        $PathName = $service.Pathname
        $StartMode = $service.Startmode
        $Caption = $service.Caption
        $Description = $service.Description 
        $Started = $service.Started
        $StartName = $service.StartName
        $State = $service.state

        $DisplayNameClean = $DisplayName -replace ',',' '
        $CaptionClean = $Caption -replace ',',' '
        $DescriptionClean = $Description -replace ',',' '

        write-output "$Hostname,$Name,$DisplayNameClean,$PathName,$StartMode,$CaptionClean,$DescriptionClean,$Started,$StartName,$State" | Out-File -FilePath $outfile -Append -Encoding ASCII
    }
}


Function Hunt-Startup-StartFolder () {
   
   $outfile = "$tempDir\$hostname-$timestamp-StartupFolder.csv"
   $Users = Get-ChildItem "C:\Users" -force | Where-Object {$_.mode -match "d"} | foreach { $_.Name }

   ForEach ($User in $Users){
        $location = "C:\Users\$User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        Get-ChildItem -Force $location -name -ErrorAction SilentlyContinue | foreach {
            write-output "$hostname,$user,$location\$_" | Out-File -FilePath $outfile -Append -Encoding ASCII  
            }
     }
}



Function Hunt-Startup-Registry () {

    $outfile = "$tempDir\$hostname-$timestamp-StartupRegistry.csv"

    $paths = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup",
    "HKU\.Default\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKU\.Default\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\Software\Microsoft\Active Setup\Installed Components",
    "HKLM:\System\CurrentControlSet\Services\VxD",
    "HKCU:\Control Panel\Desktop",
    "HKLM:\System\CurrentControlSet\Control\Session Manager",
    "HKCR:\vbsfile\shell\open\command",
    "HKCR:\vbefile\shell\open\command",
    "HKCR:\jsfile\shell\open\command",
    "HKCR:\jsefile\shell\open\command",
    "HKCR:\wshfile\shell\open\command",
    "HKCR:\wsffile\shell\open\command",
    "HKCR:\exefile\shell\open\command",
    "HKCR:\comfile\shell\open\command",
    "HKCR:\batfile\shell\open\command",
    "HKCR:\scrfile\shell\open\command",
    "HKCR:\piffile\shell\open\command",
    "HKLM:\System\CurrentControlSet\Services",
    "HKLM:\System\CurrentControlSet\Services\Winsock2\Parameters\Protocol_Catalog\Catalog_Entries",
    "HKLM:\System\Control\WOW\cmdline",
    "HKLM:\System\Control\WOW\wowcmdline", 
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\run", 
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\load", 
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run", 
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run"

    foreach ($path in $paths) {
        Set-Location -Path $path -ErrorAction SilentlyContinue
        $regkeys = Get-Item . -ErrorAction SilentlyContinue |  Select-Object -ExpandProperty property |  ForEach-Object { New-Object psobject -Property @{“property”=$_;“Value” = (Get-ItemProperty -Path . -Name $_).$_}   }

        foreach ($key in $regkeys) {
            $value = $key.Value
            $property = $key.Property
            write-output "$hostname,$path,$Property,$value" | Out-File -FilePath $outfile -Append -Encoding ASCII  
            }
        }
}




#########################################
# ---------- Account Functions -------- #
#########################################

Function Hunt-Accounts-LocalUsers () {

    $all_lusers = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select Name, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID 
    $outfile = "$tempDir\$hostname-$timestamp-LocalUsers.csv"

    foreach ($luser in $all_lusers) {
        $name = $luser.Name
        $disabled = $luser.Disabled    
        $accounttype = $luser.AccountType      
        $lockout = $luser.Lockout    
        $pwrequried = $luser.PasswordRequired    
        $pwchangeable = $luser.PasswordChangeable    
        $sid = $luser.SID    
        write-output "$hostname,$name,$disabled,$accounttype,$lockout,$pwrequried,$pwchangeable,$sid" | Out-File -FilePath $outfile -Append -Encoding ASCII
        }
}



Function Hunt-Accounts-LocalGroups () {

	$outfile = "$tempDir\$hostname-$timestamp-LocalGroups.csv"
	$groups = get-wmiobject win32_group  -Filter “LocalAccount=True”  -ComputerName $env:COMPUTERNAME | where {$_.Domain -eq  $env:COMPUTERNAME}
	
	foreach ($group in $groups) {
    $groupname = $group.Name
    $GroupMemberships = Get-GroupMember -ComputerName $env:COMPUTERNAME -LocalGroup $groupname
    $members = $GroupMemberships.Member -join ';'
    write-output "$hostname, $groupname, $members" | Out-File -FilePath $outfile -Append -Encoding ASCII
    }

}




#########################################
# ---------- System  Functions -------- #
#########################################

Function Hunt-System-InstalledSoftware () {

    $InstalledSoftware = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
    $outfile = "$tempDir\$hostname-$timestamp-InstalledSoftware.csv"

    foreach ($Software in $InstalledSoftware) {
        $DisplayName = $Software.DisplayName
        $DisplayVersion = $Software.DisplayVersion    
        $Publisher = $Software.Publisher      
        $InstallDate = $Software.InstallDate    
 
        $DisplayVersion = $DisplaYversion -replace ',',' '
        $Publisher = $Publisher -replace ',',' '
        $DisplayName = $DisplayName -replace ',',' '



        $string = "$hostname,$DisplayName,$DisplayVersion,$Publisher,$InstallDate"

        if ($string -ne "$hostname,,,,") {write-output "$hostname,$DisplayName,$DisplayVersion,$Publisher,$InstallDate" | Out-File -FilePath $outfile -Append -Encoding ASCII}
        }
}


#########################################
# ---------- Global Variables --------- #
#########################################

#set hostname to hunt as computer name
$hostname = $env:COMPUTERNAME

#Set output location
$tempDir = "C:\windows\temp\HuntLogs"

#set timestamp
$timestamp = Get-Date -format yyyyMMdd



#########################################
# --------   Start Baselining   ------- #
#########################################

# [File Functions]
Hunt-GetFiles-Exe
Hunt-GetFiles-Cmd
Hunt-GetFiles-Bat
Hunt-GetFiles-DLL
Hunt-GetFiles-PS1
Hunt-GetFiles-ADS
Hunt-GetFiles-Drivers


# [Network Functions]
Hunt-Network-NetStat
Hunt-Network-HostFile
Hunt-Network-EnabledFWRules
Hunt-Network-MappedDrives


# [Startup Functions]
Hunt-Startup-SchedTasks
Hunt-Startup-Services
Hunt-Startup-StartFolder
Hunt-Startup-Registry


# [Account Functions]
Hunt-Accounts-LocalUsers
Hunt-Accounts-LocalGroups


# [System Functions]
Hunt-System-InstalledSoftware


# [Final Zip of all files]
$sourcedir = $tempDir
$zipfilename = "$env:TEMP\HuntLogs.zip"
Add-Type -Assembly System.IO.Compression.FileSystem
$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
[System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)
Copy-Item -Path $zipfilename -Destination "$tempDir\HuntLogs.zip"


#Add in module to upload zip to php page.