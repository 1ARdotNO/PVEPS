#-----Script Info---------------------------------------------------------------------------------------------
# Name:PVEPS.psm1
# Author: Einar Stenberg 
# mail:einar@stenberg.im
# Date: 09.03.15
# Version: 1
# Job/Tasks: Powershell module for interfacing with Proxmox VE
#--------------------------------------------------------------------------------------------------------------


#-----Changelog------------------------------------------------------------------------------------------------
#v1.  Script created ES
#
#--------------------------------------------------------------------------------------------------------------





#-----Functions---------------------------------------------------------------------------------------------

Function Connect-PVE {
<#
.SYNOPSIS
Pulls updates for ESPS and other included modules from source
.DESCRIPTION
Requests credentials and creates a session with Azure instance to be used with session terminator cmdlets
Part of PVEPS by ES
.EXAMPLE
Connect-PVE https://server.com:8006
#>

Param(
[string]$hostname,
[int]$port = "8006",
[string]$Username,
[string]$Password,
[switch]$SSLValidationdisable,
[switch]$Renew
)

If ($SSLValidationdisable){
    #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    Set-StrictMode -Version 2
 
    # You have already run this function
    if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -eq 'IgnoreCerts') { Return }
 
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
    $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
    $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
    $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
    $ILGen = $MethodBuilder.GetILGenerator()
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
    $TypeBuilder.CreateType() | Out-Null
 
    # Disable SSL certificate validation
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts

}

If ($Username -and $Password -and $hostname -and !$Renew){
    
   
    
    write-verbose "Connecting to server for ticketrequest"
    $ticket= Invoke-RestMethod -Uri "https://${hostname}:$port/api2/extjs/access/ticket" -body @{username=$username;password=$password} -Method post
    
    #Check if ticketrequest was ok
    If ($ticket.success -eq "1"){
        Write-Verbose "Ticketrequest successfull"
        write-verbose "Creating WebSession"
        $cookie=New-Object System.Net.Cookie("PVEAuthCookie",$Ticket.data.ticket,"",$hostname)
        $session= New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.Cookies.Add($cookie)
    }
    else {Write-host "Ticketrequest failed!"}

}


If (!$Username -and !$Password -and !$hostname -and $Renew){
    
    $password=$PVETicket.data.ticket
    $ticket= Invoke-RestMethod -Uri "https://${PVEHostname}:$PVEPort/api2/extjs/access/ticket" -body @{username=$PVEUser;password=$password} -Method post

     #Check if ticketrequest was ok
    If ($ticket.success -eq "1"){
        Write-Verbose "Ticketrequest successfull"
        write-verbose "Creating WebSession"
        $cookie=New-Object System.Net.Cookie("PVEAuthCookie",$Ticket.data.ticket,"",$PVEhostname)
        $session= New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.Cookies.Add($cookie)
    }
    else {Write-host "Ticketrenewal failed!"}
}


#Make variables global
$Global:PVETicket = $ticket
$Global:PVESession = $session
$Global:PVETicketTime = (get-date)

If (!$renew){
    $Global:PVEHostname = $hostname
    $Global:PVEPort = $port
    $Global:PVEUser = $username
}
}


Function Get-PVECT{
[CmdletBinding()]
Param(
[parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
[string]$node = "*",
[string]$vmid = "*"
)

BEGIN{
    #Renew ticket
    $timespan=New-TimeSpan -Hours 1
    If (((get-date) - $PVETicketTime) -gt $timespan){
        Connect-PVE -Renew
    }

    #Get nodelist
    $nodes=Invoke-RestMethod -Method get -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes"
}
PROCESS{
    $nodes.data | where {$_.node -like $node} | ForEach-Object {
        #Variables
        $tempnode=$_.node

        #Openvz
        $openvz=Invoke-RestMethod  -Method get -WebSession $PVEsession -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$tempnode/openvz"
    
        #Openvz BEGIN foreach
        $openvz.data | where {$_.vmid -like $vmid} | ForEach-Object {
        
            $tempvmid=$_.vmid
            #Get config data
            $vmconfig=Invoke-RestMethod  -Method get -WebSession $PVEsession -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$tempnode/openvz/$tempvmid/config"
        
            #Arranges information into object
            $vmtemp= @{}
            $vmtemp.vmid=$_.vmid
            $vmtemp.name=$_.name
            $vmtemp.type=$_.type
            $vmtemp.status=$_.status
            $vmtemp.ip_address=$vmconfig.data.ip_address
            $vmtemp.description=$vmconfig.data.description
            $vmtemp.cpus=$_.cpus
            $vmtemp.memory=$vmconfig.data.memory
            $vmtemp.disk=$vmconfig.data.disk
            $vmtemp.storage=$vmconfig.data.storage
            $vmtemp.swap=$vmconfig.data.swap
            $vmtemp.node=$tempnode
            $vm = New-Object -TypeName psobject -Property $vmtemp
        
            #outputs final vm object
            Write-Output $vm
        }
    }
}
}


Function Get-PVEVM{

[CmdletBinding()]
Param(
[parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
[string]$node = "*",
[string]$vmid = "*"
)
BEGIN{

    #Renew ticket
    $timespan=New-TimeSpan -Hours 1
    If (((get-date) - $PVETicketTime) -gt $timespan){
       Connect-PVE -Renew
    }

    #Get nodelist
    $nodes=Invoke-RestMethod -Method get -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes"
}

PROCESS{
    $nodes.data | where {$_.node -like $node} | ForEach-Object {
        #Variables
        $tempnode=$_.node

        #Qemu
        $qemu=Invoke-RestMethod  -Method get -WebSession $PVEsession -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$tempnode/qemu"

        #Openvz BEGIN foreach
        $qemu.data | where {$_.vmid -like $vmid} | ForEach-Object {
        
            $tempvmid=$_.vmid
        
            $vmconfig=Invoke-RestMethod  -Method get -WebSession $PVEsession -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$tempnode/qemu/$tempvmid/config"
        
            #Arranges information into object
            $vmtemp= @{}
            $vmtemp.vmid=$_.vmid
            $vmtemp.name=$_.name
            $vmtemp.type="qemu"
            $vmtemp.status=$_.status
            $vmtemp.cpus=$_.cpus
            $vmtemp.memory=$vmconfig.data.memory
            $vmtemp.ostype=$vmconfig.data.ostype
            $vmtemp.description=$vmconfig.data.description
            $vmtemp.network=$vmconfig.data | select "net*"
            $vmtemp.storage=$vmconfig.data | select "virtio*","ide*","scsi*","sata*"
            $vmtemp.bootdisk=$vmconfig.data.bootdisk
            $vmtemp.balloon=$vmconfig.data.balloon
            $vmtemp.node=$tempnode
            $vm = New-Object -TypeName psobject -Property $vmtemp
        
            #outputs final vm object
            Write-Output $vm
        }
    }
}
}


Function Get-PVENode{

[CmdletBinding()]
Param(
[parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
[string]$node = "*"
)

BEGIN{
    #Renew ticket
    $timespan=New-TimeSpan -Hours 1
    If (((get-date) - $PVETicketTime) -gt $timespan){
        Connect-PVE -Renew
    }
    #Make webrequest
    $nodes=Invoke-RestMethod -Method get -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes"
}


PROCESS{

    $nodes.data | where {$_.node -like $node} | ForEach-Object {

        $nodetemp= @{}
        $nodetemp.node = $_.node
        $nodetemp.cpu = $_.cpu
        $nodetemp.id = $_.id
        $nodetemp.maxcpu = $_.maxcpu
        $nodetemp.uptime = $_.uptime
        $nodetemp.maxmem = $_.maxmem
        $nodetemp.mem = $_.mem
        $nodetemp.disk = $_.disk
        $nodetemp.maxdisk = $_.maxdisk
        $nodetemp.type = $_.type
        $nodetemp.level = $_.level

        $finalnode = New-Object -TypeName psobject -Property $nodetemp
        #outputs final node object
        Write-Output $finalnode
    }
}
}


Function Set-PVEVM{

[CmdletBinding()]
Param(
[parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
[int]$vmid,
[switch]$Start,
[switch]$Stop,
[switch]$Reset,
[switch]$Shutdown,
[switch]$Remove,
[int]$memory,
[int]$cores,
[int]$Sockets
)

BEGIN{
    #Renew ticket
    $timespan=New-TimeSpan -Hours 1
    If (((get-date) - $PVETicketTime) -gt $timespan){
        Connect-PVE -Renew
    }
}

PROCESS{
    Write-verbose "Processing VMID $vmid"
    #Find VM node
    $node=(Get-PVEVM -vmid $vmid).node
    

    #StartVM
    If ($Start -and !$Stop-and !$Reset -and !$Shutdown){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/status/start"
        If ($result.success -eq "1"){
            Write-Verbose "Start command Successfull!"
            Write-Output "Start of $vmid OK"
            Write-Output $result.message
        }
        Else{
            Write-host "Start of $vmid Failed"
            Write-Output $result.message
        }
    }

    #StopVM
    If ($Stop -and !$start-and !$Reset -and !$Shutdown){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/status/stop"
        If ($result.success -eq "1"){
            Write-Verbose "Stop command Successfull!"
            Write-Output "Stop of $vmid OK"
            Write-Output $result.message
        }
        Else{
            Write-host "Stop of $vmid Failed"
            Write-Output $result.message
        }
    }

    #ResetVM
    If ($Reset -and !$Stop -and !$start -and !$Shutdown){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/status/reset"
        If ($result.success -eq "1"){
            Write-Verbose "Reset command Successfull!"
            Write-Output "Reset of $vmid OK"
            Write-Output $result.message
        }
        Else{
            Write-host "Reset of $vmid Failed"
            Write-Output $result.message
        }
    }
    
    #ShutdownVM
    If ($Shutdown -and !$Reset -and !$Stop -and !$start){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/status/shutdown"
        If ($result.success -eq "1"){
            Write-Verbose "Shutdown command Successfull!"
            Write-Output "Shutdown of $vmid OK"
            Write-Output $result.message
        }
        Else{
            Write-host "Shutdown of $vmid Failed"
            Write-Output $result.message
        }
    }

    #RemoveVM
    If ($Remove){
        $result=Invoke-RestMethod -Method Delete -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid"
        If ($result.success -eq "1"){
            Write-Verbose "Remove command Successfull!"
            Write-Output "Remove of $vmid OK"
            Write-Output $result.message
        }
        Else{
            Write-host "Remove of $vmid Failed"
            Write-Output $result.message
        }
    }

    #Changememory
    If ($memory){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession -Body @{memory=$memory}  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/config/"
        If ($result.success -eq "1"){
            Write-Output "Memory of $vmid changed to $memory MB"
            Write-Output $result.message
        }
        Else{
            Write-host "Memory change of $vmid Failed"
            Write-Output $result.message
        }
    }
    #ChangeCores
    If ($Cores){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession -Body @{cores=$cores}  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/config/"
        If ($result.success -eq "1"){
            Write-Output "Cores of $vmid changed to $cores cores"
            Write-Output $result.message
        }
        Else{
            Write-host "Cores change of $vmid Failed"
            Write-Output $result.message
        }u
    }
    #Changesockets
    If ($Sockets){
        $result=Invoke-RestMethod -Method Post -Headers @{CSRFPreventionToken=$PVETicket.data.CSRFPreventionToken} -WebSession $PVEsession -Body @{sockets=$Sockets}  -Uri "https://${PVEhostname}:$PVEport/api2/extjs/nodes/$node/qemu/$vmid/config/"
        If ($result.success -eq "1"){
            Write-Output "Sockets of $vmid changed to $Sockets Sockets"
            Write-Output $result.message
        }
        Else{
            Write-host "Sockets change of $vmid Failed"
            Write-Output $result.message
        }
    }
}
}
