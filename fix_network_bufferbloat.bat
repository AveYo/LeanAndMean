@(set ^ "f0=%temp%\FixNetworkBufferbloat.ps1" -desc ')|| AveYo, 2024.10.17
@(fc %0 "%f0%" 2>&1||copy /b %0+nul "%f0%" /y)>nul& powershell -nop -ep RemoteSigned -f "%f0%" %* -dp0 "%CD%"
@exit /b '); . { Param($dp0 = $pwd.Path); $dp0 = $dp0.Trim('" \'); $n0 = ${^}-replace'^.+\\|.{4}$',''; cd -l "$dp0\" -ea 0

write-host @'

  FixNetworkBufferbloat - test on waveform.com/tools/bufferbloat and speedtest.net
  You should upgrade to a router with fast cpu and ram having Smart Queue Management 
  This script is no SQM, but just a short term network configuration! 
  Can apply both, tho I recommend only using the upload bufferbloat fix:  
  Upload QoS ON - prioritizes outbound traffic, keeping download gigabit speeds
  Download Autotuning OFF - disables TCP Window Scaling, hurting gigabit speeds 

'@

#:: Args / Dialog - can use commandline parameters to skip the prompt
$cl = @{2 = 'both'; 1 = 'upload'; 0 = 'download'; -1 = 'reset'}
$do = ''; foreach ($a in $cl.Values) { if ($args -contains $a) {$do = $a} } ; if ($do -eq '') {
  $UL = "ON"; if (!(Get-NetQosPolicy -name "Bufferbloat" -ea 0)) {$UL = "OFF"} ; $d = Get-NetTCPSetting -SettingName internet
  $DL = "ON"; if ($d.AutoTuningLevelLocal -eq "Disabled" -or $d.AutoTuningLevelGroupPolicy -eq "Disabled") {$DL = "OFF"}
  $choice = (new-object -ComObject Wscript.Shell).Popup("Upload QoS $UL  ,  Download Autotuning $DL  ,  Reset", 0, "$n0", 0x1043)
  if ($choice -eq 2) {$do = $cl.-1} elseif ($choice -eq 6) {$do = $cl.1} else {$do = $cl.0} ; $args = ,$do
}

#:: Elevate
if ($true -and [Security.Principal.WindowsIdentity]::GetCurrent().Groups -notcontains "S-1-5-32-544") {
  write-host " Requesting ADMIN rights.. " -fore 0 -back 0xE ; sleep 2
  $f0 = $MyInvocation.ScriptName; $a0 = $args -replace'"','\"' -replace'(.*\s.*)','"$1"'; if (!$f0) {
    $lean_and_mean_hybrid_header = "`@(set ^ `"$((gv ^).Value)`" -desc '$((gv ^).Description)'); . {" + 
    $MyInvocation.MyCommand + "} `@args; return; `${ press Enter if copy-pasted in powershell }"
    $f0 = "$env:temp\$n0.ps1"; sc $f0 $($lean_and_mean_hybrid_header-split'\r?\n') -force } 
  start powershell -verb runas -work \ -args "-nop -ep RemoteSigned -f `"$f0`" $a0 -dp0 `"$dp0`" "; return
}

#:: Do
if ($MyInvocation.ScriptName) {$host.ui.RawUI.WindowTitle = "$n0 $do"}
$NIC = @()
foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID,Name) { 
  $NIC += @{ $($a | Select Name -ExpandProperty Name) = $($a | Select DeviceID -ExpandProperty DeviceID) }
}
$NICs = $NIC.Keys -join ', '

if ($do -eq 'upload' -or $do -eq 'both') {
  $RWSCALING = 'Normal'; $QoS = 50; $MBW = $QoS - 1
  write-host " Upload QoS ON" -fore Yellow; . {
    ni "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" 1 -type string -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableUserTOSSetting 0 -type dword -force -ea 0
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" NonBestEffortLimit $QoS -type dword -force -ea 0 # 80
    Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
    Remove-NetQosPolicy "Bufferbloat" -Confirm:$False -ea 0
    New-NetQosPolicy "Bufferbloat" -Precedence 254 -DSCPAction 46 -NetworkProfile Public -Default -MinBandwidthWeightAction $MBW
  } 2>'' 1>''
}

if ($do -eq 'download' -or $do -eq 'both') {
  $RWSCALING = 'Disabled'
  write-host " Download Autotuning OFF" -fore Yellow; . {
    rp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "Tcp Autotuning Level" -force -ea 0
  } 2>'' 1>''
}

if ($do -ne 'reset') {
  " SG TCPOptimizer tweaks"; . {
    $NIC.Values |foreach {
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency 2 -type dword -force -ea 0  #1
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay 1 -type dword -force -ea 0
    }
    if (gi "HKLM:\SOFTWARE\Microsoft\MSMQ") {sp "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" TCPNoDelay 1 -type dword -force -ea 0}
    sp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" NetworkThrottlingIndex 0xffffffff -type dword -force -ea 0
    sp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" SystemResponsiveness 10 -type dword -force -ea 0
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" NonBestEffortLimit $QoS -type dword -force -ea 0 # 80
    sp "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" LargeSystemCache 0 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" Size 3 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DefaultTTL 64 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaxUserPort 65534 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" TcpTimedWaitDelay 30 -type dword -force -ea 0
    ni "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" 1 -type string -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" DnsPriority 6 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" HostsPriority 5 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" LocalPriority 4 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" NetbtPriority 7 -type dword -force -ea 0
  } 2>'' 1>''

  " Other registry tweaks"; . {
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableTaskOffload -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaximumReassemblyHeaders 0xffff -type dword -force -ea 0 # 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" FastSendDatagramThreshold 1500 -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultReceiveWindow $(2048 * 4096) -type dword -force -ea 0
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultSendWindow $(4096 * 4096) -type dword -force -ea 0
  }

  " temporarily disable $NICs"; . { $NIC.Keys | foreach { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

  " Set-NetAdapterAdvancedProperty"; . { $NIC.Keys |foreach {
  # reset advanced 
    $mac = $(Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -ea 0).RegistryValue
    Get-NetAdapter -Name "$_" | Reset-NetAdapterAdvancedProperty -DisplayName "*"
  # restore custom mac
    if ($mac) { Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -RegistryValue $mac }
  # set receive and transmit buffers - less is better for latency, worst for throughput; too less and packet loss increases
    $rx = (Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*ReceiveBuffers").NumericParameterMaxValue  # $rx 1024 320
    $tx = (Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*TransmitBuffers").NumericParameterMaxValue # $tx 2048 160
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*ReceiveBuffers"  -RegistryValue $([math]::min($rx,1024))
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*TransmitBuffers" -RegistryValue $([math]::min($tx,2048))
  # pci-e adapters in msi-x mode from intel are generally fine with ITR Adaptive - others? not so much
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*InterruptModeration" -RegistryValue 0 # Off 0 On 1
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "ITR" -RegistryValue 0 # Off 0 Adaptive 65535
  # recieve side scaling is always worth it, some adapters feature more queues = cpu threads; not available for wireless   
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*RSS" -RegistryValue 1
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*NumRssQueues" -RegistryValue 2
  # priority tag
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*PriorityVLANTag" -RegistryValue 1
  # undesirable stuff 
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*FlowControl" -RegistryValue 3
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*JumboPacket" -RegistryValue 1514
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*HeaderDataSplit" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "TcpSegmentation" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "RxOptimizeThreshold" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "WaitAutoNegComplete" -RegistryValue 1
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "PowerSavingMode" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*SelectiveSuspend" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "EnableGreenEthernet" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "AdvancedEEE" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "EEE" -RegistryValue 0
    Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*EEE" -RegistryValue 0
  } } 2>'' 1>''

  " Set-NetOffloadGlobalSetting"; . {
    Set-NetOffloadGlobalSetting -TaskOffload Enabled # Disabled
    Set-NetOffloadGlobalSetting -Chimney Disabled
    Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled
    Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
    Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled
    Set-NetOffloadGlobalSetting -NetworkDirect Enabled
    Set-NetOffloadGlobalSetting -NetworkDirectAcrossIPSubnets Allowed -ea 0 # Blocked
  } #2>'' 1>''

  " Enable-NetAdapterRss"; . { $NIC.Keys |foreach {
    Set-NetAdapterRss -Name "$_" -NumberOfReceiveQueues 2 -BaseProcessorNumber 2 -MaxProcessorNumber 4 -Profile $(
      "NUMAStatic") -Enabled $true -ea 0
    Enable-NetAdapterQos -Name "$_" -ea 0
    Enable-NetAdapterChecksumOffload -Name "$_" -ea 0

    Disable-NetAdapterRsc -Name "$_" -ea 0
    Disable-NetAdapterUso -Name "$_" -ea 0
    Disable-NetAdapterLso -Name "$_" -ea 0
    Disable-NetAdapterIPsecOffload -Name "$_" -ea 0
    Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "$_" -ea 0
  } } #2>'' 1>''

  " enable $NICs"; . { $NIC.Keys | foreach { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

  " netsh tweaks"; . {
    netsh winsock set autotuning on                                    # Winsock send autotuning
    netsh int udp set global uro=disabled                              # UDP Receive Segment Coalescing Offload - 11 24H2
    netsh int tcp set heuristics wsh=disabled forcews=disabled          # Window Scaling heuristics
    netsh int tcp set supplemental internet minrto=300                 # Controls TCP retransmission timeout. 20 to 300 msec.
    netsh int tcp set supplemental internet icw=10                     # Controls initial congestion window. 2 to 64 MSS
    netsh int tcp set supplemental internet congestionprovider=dctcp   # Controls the congestion provider. cubic ctcp dctcp 
    netsh int tcp set supplemental internet enablecwndrestart=enabled  # Controls whether congestion window is restarted.
    netsh int tcp set supplemental internet delayedacktimeout=40       # Controls TCP delayed ack timeout. 10 to 600 msec.
    netsh int tcp set supplemental internet delayedackfrequency=2      # Controls TCP delayed ack frequency. 1 to 255.
    netsh int tcp set supplemental internet rack=enabled               # Controls whether RACK time based recovery is enabled.
    netsh int tcp set supplemental internet taillossprobe=enabled      # Controls whether Tail Loss Probe is enabled.
    netsh int tcp set security mpp=disabled                            # Memory pressure protection (SYN flood drop)
    netsh int tcp set security profiles=disabled                       # Profiles protection (private vs domain)

    netsh int tcp set global rss=enabled                    # Enable receive-side scaling.
    netsh int tcp set global autotuninglevel=$RWSCALING     # Fix the receive window at its default value  highlyrestricted normal
    netsh int tcp set global ecncapability=enabled          # Enable/disable ECN Capability.
    netsh int tcp set global timestamps=enabled             # Enable/disable RFC 1323 timestamps.
    netsh int tcp set global initialrto=1000                # Connect (SYN) retransmit time (in ms). default: 1000.
    netsh int tcp set global rsc=disabled                   # Enable/disable receive segment coalescing.
    netsh int tcp set global nonsackrttresiliency=disabled  # Enable/disable rtt resiliency for non sack clients. default: disabled
    netsh int tcp set global maxsynretransmissions=2        # Connect retry attempts using SYN packets. default: 2.
    netsh int tcp set global fastopen=enabled               # Enable/disable TCP Fast Open.
    netsh int tcp set global fastopenfallback=enabled       # Enable/disable TCP Fast Open fallback.
    netsh int tcp set global hystart=enabled                # Enable/disable the HyStart slow start algorithm.
    netsh int tcp set global prr=enabled                    # Enable/disable the Proportional Rate Reduction algorithm.
    netsh int tcp set global pacingprofile=off              # Set the periods during which pacing is enabled. off: Never pace.

    netsh int ip set global loopbacklargemtu=enable         # Loopback Large Mtu
    netsh int ip set global loopbackworkercount=4           # Loopback Worker Count 1 2 4
    netsh int ip set global loopbackexecutionmode=adaptive  # Loopback Execution Mode adaptive|inline|worker
    netsh int ip set global reassemblylimit=267748640       # Reassembly Limit 267748640|100238784|94371840|0
    netsh int ip set global sourceroutingbehavior=drop      # Source Routing Behavior drop|dontforward
    netsh int ip set dynamicport tcp start=32769 num=32766  # DynamicPortRange tcp
    netsh int ip set dynamicport udp start=32769 num=32766  # DynamicPortRange udp
  } 2>'' 1>''

  # . { gpupdate /force } 2>'' 1>''
}

if ($do -eq 'reset') {
  write-host " Reset" -fore Yellow
  " Reset SG TCPOptimizer tweaks"; . {
    $NIC.Values |foreach {
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpDelAckTicks -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay -force -ea 0
    }
    if (gi "HKLM:\SOFTWARE\Microsoft\MSMQ") {rp "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" TCPNoDelay -force -ea 0}
    rp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" NetworkThrottlingIndex -force -ea 0
    rp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" SystemResponsiveness -force -ea 0
    rp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" NonBestEffortLimit -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" LargeSystemCache -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" Size -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DefaultTTL -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaxUserPort -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" TcpTimedWaitDelay -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" DnsPriority -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" HostsPriority -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" LocalPriority -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" NetbtPriority -force -ea 0
  } 2>'' 1>''

  " Reset other registry tweaks"; . {
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" FastSendDatagramThreshold -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultSendWindow -force -ea 0 #16777216
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultReceiveWindow -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" IRPStackSize -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableTaskOffload -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaximumReassemblyHeaders -force -ea 0  # 0
  } 2>'' 1>''

  " Temporarily disable $NICs"; . { $NIC.Keys | foreach { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

  " Reset-NetAdapterAdvancedProperty"; . { $NIC.Keys |foreach {
    $mac = $(Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -ea 0).RegistryValue
    Get-NetAdapter -Name "$_" | Reset-NetAdapterAdvancedProperty -DisplayName "*"
    if ($mac) { Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -RegistryValue $mac }
  } } 2>'' 1>''

  " Re-enable $NICs"; . { $NIC.Keys | foreach { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

  " Reset netsh"; . {
    netsh int ip reset; netsh int ipv6 reset; netsh int ipv4 reset; netsh int tcp reset; netsh int udp reset; netsh winsock reset
    netsh int ip set dynamicport tcp start=49152 num=16384; netsh int ip set dynamicport udp start=49152 num=16384
  } 2>'' 1>''

  " Reset QoS"; . {
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DefaultTOSValue -force -ea 0
    rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableUserTOSSetting -force -ea 0
    rp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "Tcp Autotuning Level" -force -ea 0
    Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
  } 2>'' 1>''
  
  . { gpupdate /force } 2>'' 1>''
}

#:: show network configuration
function ps: { write-host -fore cyan "`npowershell" @args; $(powershell @args 2>'' | out-string).Trim("`r","`n") } #
function ns: { write-host -fore cyan "`nnetsh" @args; $(netsh @args 2>'' | out-string).Trim("`r","`n") }
ps: Get-NetTransportFilter `|ft
ps: Get-NetAdapterHardwareInfo #`| fl
ps: Get-SmbClientNetworkInterface
ps: Get-NetAdapterRSS `|ft
ps: Get-NetAdapterChecksumOffload
ps: Get-NetAdapterLso
ps: Get-NetOffloadGlobalSetting `|ft
ps: Get-NetQosPolicy
ns: int ip show interfaces
ns: int ipv4 show global
ns: int tcp show supplemental
ns: int tcp show global
ns: winsock show autotuning
ps: Get-NetTCPSetting -SettingName internet  
timeout -1

} @args; return; ${ press Enter if copy-pasted in powershell }
