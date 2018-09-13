# PVEPS
Powershell functions to interact with Proxmox VE REST API

Work in progress, needs work on login ticket refreshing, otherwise most commands work fin with pipeline options between them.

Example commands,

Connect-PVE -hostname 192.168.0.123 -Username "root@pam" -Password "topsecret" -SSLValidationdisable
$PVETicket.data.ticket



Get-PVEVM -vmid 105 | Set-PVEVM -Start -Verbose
Get-PVEVM -vmid 105 | Set-PVEVM -Stop -Verbose
Get-PVEVM -vmid 105 | Set-PVEVM -reset -Verbose
Get-PVEVM -vmid 105 | Set-PVEVM -Shutdown -Verbose



Get-PVECT -vmid 154
Get-PVEvm -vmid 260

Get-PVEct | get-pvenode
Get-PVEVM | get-pvenode

Get-PVENode | Get-PVEct
Get-PVENode | Get-PVEVM

Connect-PVE -Renew
