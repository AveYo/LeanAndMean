@(set "0=%~f0" '& set 1=%*) & powershell -nop -c "type -lit $env:0 | out-string | powershell -nop -c -" & exit /b ');.{
write-host @"
`n
  FixNetworkBufferbloat - AveYo, 2025.11.11
  test on waveform.com/tools/bufferbloat , speed.cloudflare.com , speedtest.net
  You should upgrade to a router with fast cpu and ram having Smart Queue Management
  This script is no SQM, but just a short term network limits configuration!
  to skip the dialog use cmd parameters or rename script ex: fix_network_bufferbloat upload.bat
  Upload fix limits up speeds, Download fix limits single-part dl, but games benefit!
  Phone tethering or poor wireless signal? Should select Both
`n
"@
##  2025.11.11 reduce upload speed drop; show network summary
##  2025.09.15 tuned buffers
##  2025.07.12 refactored and improved dialog (Upload,Download,Both,Cancel)
##  2025.02.06 upload fix now works on Home editions too!!!
##  2024.11.20 do not change disabled adapters; revert order to Yes = Upload fix, No = Download fix
##  2024.11.19 good improvements even on shitty 4G hotspot, do a reset then try upload fix first

$id = 'FixNetworkBufferbloat'
$cl = ''; $do = @{1 = 'upload'; 2 = 'download'; 3 = 'both'; 4 = 'reset'; 5 = 'cancel'}
$f0 = ($env:0,"$pwd\.pasted")[!$env:0]
foreach ($a in $do.Values) { if ("$(split-path $f0 -leaf) $env:1" -like "*$a*") {$cl = $a} }
function Choices($all, $def, $n='Options', [byte]$sz=12, $bc='MidnightBlue', $fc='Snow') {
  [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); $f=new-object Windows.Forms.Form; $f.MaximizeBox=0
  $def--; $bt=@(); $r=1; $l = new-object Windows.Forms.FlowLayoutPanel; $l.FlowDirection=0; $l.Anchor = 5; $l.AutoSize=1
  $all.split(',').Trim() | foreach { $b=new-object Windows.Forms.Button; $bt+=$b; $b.Tag=$r++; $b.Text=$_; $b.AutoSize=1
  $b.add_GotFocus({$this.BackColor=$fc; $this.ForeColor=$bc}); $b.add_LostFocus({$this.BackColor=$bc; $this.ForeColor=$fc})
  $b.Font='Tahoma,'+$sz; $b.Margin='10,32,10,32'; $b.add_Click({$env:ret=$this.Tag; $f.Dispose()}); $l.Controls.Add($b) }
  $f.Controls.Add($l); $f.Text=$n; $f.BackColor=$bc; $f.ForeColor=$fc; $f.FormBorderStyle=3; $f.AutoSizeMode=0; $f.AutoSize=1
  $f.StartPosition=4; $f.CancelButton=$bt[$def]; $f.Add_Shown({$bt[$def].focus()}); [void]$f.ShowDialog(); return [int]$env:ret
}
$UF = (" ",[char]0x2713)[(gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "U fix" -ea 0) -ne $null]
$DF = (" ",[char]0x2713)[(gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "D fix" -ea 0) -ne $null]
if ($cl -eq '') { $c = Choices "&Upload $UF, &Download $DF, &Both, &Reset, &Cancel" 5 "$id"; $cl = $do[$c] }
if ($cl -eq 'cancel') { return }

$ps = {
  $PAUSE_FOR_SUMMARY = 0
  pushd -lit $(split-path $args[0]); $do = $args[1]; $id = $args[2]; [Console]::Title = "$id $do"
  write-host

  ##  current state
  $UF = ($false,$true)[(gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "U fix" -ea 0) -ne $null]
  $DF = ($false,$true)[(gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "D fix" -ea 0) -ne $null]

  $NIC = @(); $Disabled = @()
  foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID,Name,InterfaceAdminStatus) {
    $NIC += @{ $($a | Select Name -ExpandProperty Name) = $($a | Select DeviceID -ExpandProperty DeviceID) }
    if ($a.InterfaceAdminStatus -eq 2) {$Disabled += $a | Select Name -ExpandProperty Name}
  }
  $NICs = ($NIC.Keys | where {$Disabled -notcontains $_}) -join ', '

  ## both
  $NONSACK = 'Enabled'; $RWSCALING = 'Disabled'; $UPTUNE = 'on'; $PACING = 'always'; $MARKING = 'Allowed'; $NONBESTEFFORT = 20

  if ($do -eq 'upload' -or $do -eq 'both') {
    write-host " Upload QoS Enabled" -fore Green; . {
      if ($do -eq 'upload') { $RWSCALING = 'Normal' }
      ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -recurse -force -ea 0
      ni "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -ea 0
      sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "Application DSCP Marking Request" "$MARKING" -force -ea 0
      sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "U fix" "1" -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -recurse -force -ea 0
      ni "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" 1 -type dword -force -ea 0
      ni "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableUserTOSSetting 0 -type dword -force -ea 0
      ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -recurse -force -ea 0
      ni "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -ea 0
      sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" NonBestEffortLimit $NONBESTEFFORT -type dword -force -ea 0
      "ActiveStore","GPO:$env:computername","$env:computername" | foreach {
        Get-NetQosPolicy -PolicyStore $_ | Remove-NetQosPolicy -Confirm:$False -ea 0
      }
      $qos = "Remove-NetQosPolicy -PolicyStore ActiveStore -name * -Confirm:`$false -ea 0"
      $qos+= ";New-NetQosPolicy Bufferbloat_throttle -PolicyStore ActiveStore -NetworkProfile 2 -IPProtocol TCP"
      $qos+= " -Precedence 254 -DSCPAction 24 -MinBandwidthWeightAction 2" ## 4g experiment: 2
      $qos+= ";New-NetQosPolicy Bufferbloat_priority -PolicyStore ActiveStore -NetworkProfile 2 -Default "
      $qos+= " -Precedence 252 -DSCPAction 40 -MinBandwidthWeightAction 98" ## 4g experiment: 98
      powershell -nop -c "$qos"
      $sa = New-ScheduledTaskAction -Execute powershell -Argument "-nop -c $qos"; $st = New-ScheduledTaskTrigger -AtStartup
      Register-ScheduledTask -TaskName 'Bufferbloat' -Action $sa -Trigger $st -User 'NT AUTHORITY\SYSTEM' -Force | out-null
      Start-ScheduledTask -TaskName 'Bufferbloat'
    } 2>'' 1>''
  }

  if ($do -eq 'download' -or $do -eq 'both') {
    write-host " Download Autotuning Disabled" -fore Green; . {
      if ($do -eq 'download') {
        $NONSACK = 'Disabled'; $RWSCALING = 'Disabled'; $NONBESTEFFORT = 80
        ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -recurse -force -ea 0
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "*" -force -ea 0
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableUserTOSSetting -force -ea 0
        ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -recurse -force -ea 0
        "ActiveStore","$env:computername","GPO:$env:computername" |foreach {
          Get-NetQosPolicy -PolicyStore $_ | Remove-NetQosPolicy -Confirm:$False -ea 0 }
        Unregister-ScheduledTask -TaskName 'Bufferbloat' -confirm:$false -ea 0
      }
      ni "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -ea 0
      sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "D fix" "1" -force -ea 0
      rp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" "Tcp Autotuning Level" -force -ea 0
    } 2>'' 1>''
  }

  if ($do -ne 'reset') {
    " SG TCPOptimizer tweaks"; . {
      ni "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ea 0
      $NIC | where {$Disabled -notcontains $_.Keys} |foreach { $guid = $_.Values
        sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpNoDelay 1 -type dword -force -ea 0
        sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpAckFrequency 2 -type dword -force -ea 0
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpDelAckTicks -force -ea 0
      }
      if (gi "HKLM:\SOFTWARE\Microsoft\MSMQ") {sp "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" TCPNoDelay 1 -type dword -force}
      sp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" NetworkThrottlingIndex -1 -type dword -force
      sp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" SystemResponsiveness 10 -type dword -force
      sp "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" LargeSystemCache 0 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" Size 3 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DefaultTTL 64 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaxUserPort 65534 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" TcpTimedWaitDelay 30 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" DnsPriority 6 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" HostsPriority 5 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" LocalPriority 4 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" NetbtPriority 7 -type dword -force -ea 0
    } 2>'' 1>''

    " Other registry tweaks"; . {
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" StrictTimeWaitSeqCheck 1 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" KeepAliveTime 300000 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaximumReassemblyHeaders 0xffff -type dword -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" "*" -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" FastCopyReceiveThreshold 1500 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" FastSendDatagramThreshold 1500 -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultReceiveWindow $(4096 * 2048) -type dword -force -ea 0
      sp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" DefaultSendWindow $(4096 * 2048) -type dword -force -ea 0
    }

    " Temporarily disable: $NICs"; . { $NIC.Keys | foreach { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

    " Set-NetAdapterAdvancedProperty"; . { $NIC.Keys | where {$Disabled -notcontains $_} | foreach {
    # reset advanced
      $mac = $(Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -ea 0).RegistryValue
      Get-NetAdapter -Name "$_" | Reset-NetAdapterAdvancedProperty -DisplayName "*"
    # restore custom mac
      if ($mac) { Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -RegistryValue $mac }
    # set receive and transmit buffers - less is better for latency, worst for throughput; too less and packet loss increases
      $rx = (Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*ReceiveBuffers").NumericParameterMaxValue
      $tx = (Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*TransmitBuffers").NumericParameterMaxValue
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*ReceiveBuffers"  -RegistryValue $rx ## $rx 1024 320
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*TransmitBuffers" -RegistryValue $tx ## $tx 2048 160
    # pci-e adapters in msi-x mode from intel are generally fine with ITR Adaptive - others? not so much
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*InterruptModeration" -RegistryValue 0 # Off 0 On 1
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "ITR" -RegistryValue 0 # Off 0 Adaptive 65535
    # recieve side scaling is always worth it, some adapters feature more queues = cpu threads; not available for wireless
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*RSS" -RegistryValue 1
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*NumRssQueues" -RegistryValue 2
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*RssOnHostVPorts" -RegistryValue 1
    # priority tag
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*PriorityVLANTag" -RegistryValue 3 ## 0
    # undesirable stuff
      Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "*FlowControl" -RegistryValue 0
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
      Set-NetOffloadGlobalSetting -TaskOffload Enabled
      Set-NetOffloadGlobalSetting -Chimney Disabled
      Set-NetOffloadGlobalSetting -PacketCoalescingFilter Enabled
      Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
      Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled
      Set-NetOffloadGlobalSetting -NetworkDirect Enabled
      Set-NetOffloadGlobalSetting -NetworkDirectAcrossIPSubnets Allowed -ea 0
    } 2>'' 1>''

    " Enable-NetAdapterRss"; . { $NIC.Keys | where {$Disabled -notcontains $_} | foreach {
      Set-NetAdapterRss -Name "$_" -NumberOfReceiveQueues 2 -MaxProcessorNumber 4 -Profile "NUMAStatic" -Enabled $true -ea 0
      Enable-NetAdapterQos -Name "$_" -ea 0
      Enable-NetAdapterChecksumOffload -Name "$_" -ea 0
      Disable-NetAdapterRsc -Name "$_" -ea 0
      Disable-NetAdapterUso -Name "$_" -ea 0
      Disable-NetAdapterLso -Name "$_" -ea 0
      Disable-NetAdapterIPsecOffload -Name "$_" -ea 0
      Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "$_" -ea 0
    } } 2>'' 1>''

    " Re-enable: $NICs"; . {
      $NIC.Keys | where {$Disabled -notcontains $_} | foreach { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }
    }

    " Netsh tweaks"; . {
      netsh winsock set autotuning $UPTUNE                               # Winsock send autotuning, on off
      netsh int udp set global uro=disabled                              # UDP Receive Segment Coalescing Offload - 11 24H2
      netsh int tcp set heuristics wsh=disabled forcews=disabled         # Window Scaling heuristics, disabled
      netsh int tcp set supplemental internet minrto=300                 # TCP retransmission timeout, readonly
      netsh int tcp set supplemental internet icw=10                     # Initial congestion window, readonly
      netsh int tcp set supplemental internet congestionprovider=ctcp    # Congestion provider, cubic newreno dctcp
      netsh int tcp set supplemental internet enablecwndrestart=enabled  # Congestion window restart, enabled
      netsh int tcp set supplemental internet delayedacktimeout=40       # TCP delayed ack timeout, readonly
      netsh int tcp set supplemental internet delayedackfrequency=2      # TCP delayed ack frequency, readonly
      netsh int tcp set supplemental internet rack=enabled               # RACK time based recovery, readonly
      netsh int tcp set supplemental internet taillossprobe=enabled      # Tail Loss Probe, readonly
      netsh int tcp set security mpp=disabled                            # Memory pressure protection (SYN flood drop)
      netsh int tcp set security profiles=disabled                       # Profiles protection (private vs domain)
      netsh int tcp set global rss=enabled                               # Receive-side scaling
      netsh int tcp set global autotuninglevel=$RWSCALING                # Receive window autotuning
      netsh int tcp set global ecncapability=enabled                     # ECN Capability
      netsh int tcp set global timestamps=enabled                        # RFC 1323 timestamps, allowed enabled
      netsh int tcp set global initialrto=2000                           # Connect (SYN) retransmit time (in ms)
      netsh int tcp set global rsc=disabled                              # Receive segment coalescing
      netsh int tcp set global nonsackrttresiliency=$NONSACK             # Rtt resiliency for non sack clients
      netsh int tcp set global maxsynretransmissions=4                   # Connect retry attempts using SYN packets
      netsh int tcp set global fastopen=enabled                          # TCP Fast Open, readonly
      netsh int tcp set global fastopenfallback=enabled                  # TCP Fast Open fallback, readonly
      netsh int tcp set global hystart=disabled                          # HyStart slow start algorithm
      netsh int tcp set global prr=enabled                               # Proportional Rate Reduction algorithm
      netsh int tcp set global pacingprofile=$PACING                     # TCP pacing, always slowstart initialwindow off
      netsh int ip set global loopbacklargemtu=enable                    # Loopback Large Mtu enable
      netsh int ip set global loopbackworkercount=4                      # Loopback Worker Count 1 2 4
      netsh int ip set global loopbackexecutionmode=inline               # Loopback Execution Mode, adaptive inline worker
      netsh int ip set global reassemblylimit=267748640                  # Reassembly Limit, 267748640 0
      netsh int ip set global reassemblyoutoforderlimit=128              # Reassembly Out Of Order Limit, 32
      netsh int ip set global sourceroutingbehavior=drop                 # Source Routing Behavior, drop dontforward
      netsh int ip set global sourcebasedecmp=enabled                    # Source Based ECMP (Equal Cost Multi-Path)
      netsh int ip set dynamicport tcp start=32769 num=32766             # DynamicPortRange tcp
      netsh int ip set dynamicport udp start=32769 num=32766             # DynamicPortRange udp
    } 2>'' 1>''

    " Group Policy refresh"; . {
      pushd "$env:Systemroot\System32\GroupPolicy\Machine"
      if (!(test-path "$PWD\before.pol") -and (test-path "$PWD\Registry.pol")) { ren "$PWD\Registry.pol" "before.pol" -force }
      function U2($str) { [Text.Encoding]::Unicode.GetBytes($str).ForEach('ToString', 'X2') -join ' ' }
      function L2($str) { ([BitConverter]::GetBytes($str.length * 2 + 2) |% {'{0:X2}'-f $_}) -join ' ' -replace ' 00 00$','' }
      function N2($num) { ([BitConverter]::GetBytes($num) |% {'{0:X2}'-f $_}) -join ' ' -replace ' 00 00$','' }
      $pol = "$PWD\Registry.pol"; $head = "50 52 65 67 01 00 00"; ${;} = "00 00 3B 00"
      $txt = "00 5B 00 $(U2 'Software\Policies\Microsoft\Windows\QoS') ${;} $(U2 'Application DSCP Marking Request') ${;} " +
             "01 00 ${;} $(L2 $MARKING) ${;} $(U2 $MARKING) 00 00 5D " +
             "00 5B 00 $(U2 'Software\Policies\Microsoft\Windows\Psched') ${;} $(U2 'NonBestEffortLimit') ${;} " +
             "04 00 ${;} 04 00 ${;} $(N2 $NONBESTEFFORT) 00 00 5D 00"
      [io.file]::writeallbytes($pol, ([byte[]] (-split "$head $txt" -replace '^', '0x')))
      gpupdate /Target:Computer /force
      popd
    } 2>'' 1>''
  }

  if ($do -eq 'reset') {
    write-host " Reset (Upload QoS Disabled, Download Autotuning Normal)" -fore Green

    " Reset SG TCPOptimizer tweaks"; . {
      $NIC | where {$Disabled -notcontains $_.Keys} |foreach { $guid = $_.Values
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpNoDelay -force -ea 0
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpAckFrequency -force -ea 0
        rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" TcpDelAckTicks -force -ea 0
      }
      if (gi "HKLM:\SOFTWARE\Microsoft\MSMQ") {rp "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" TCPNoDelay -force -ea 0}
      rp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" NetworkThrottlingIndex -force -ea 0
      rp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" SystemResponsiveness -force -ea 0
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
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" StrictTimeWaitSeqCheck -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" MaximumReassemblyHeaders -force -ea 0  # 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" "*" -force -ea 0
    } 2>'' 1>''

    " Temporarily disable: $NICs"; . { $NIC.Keys | foreach { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False } }

    " Reset-NetAdapterAdvancedProperty"; . { $NIC.Keys | where {$Disabled -notcontains $_} | foreach {
      $mac = $(Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -ea 0).RegistryValue
      Get-NetAdapter -Name "$_" | Reset-NetAdapterAdvancedProperty -DisplayName "*"
      if ($mac) { Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword "NetworkAddress" -RegistryValue $mac }
    } } 2>'' 1>''

    " Re-enable: $NICs"; . {
      $NIC.Keys | where {$Disabled -notcontains $_} | foreach { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }
    }

    " Reset netsh"; . {
      netsh int ip set dynamicport tcp start=49152 num=16384;    netsh int ip set dynamicport udp start=49152 num=16384
      netsh int ip set global reassemblyoutoforderlimit=32;      netsh int ip set global reassemblylimit=133793216
      netsh int ip set global sourceroutingbehavior=dontforward; netsh int ip set global sourcebasedecmp=disabled
      netsh int ip set global loopbackexecutionmode=adaptive;    netsh int ip set global loopbackworkercount=2
      netsh int ip reset; netsh int ipv4 reset; netsh int tcp reset; netsh int udp reset; netsh winsock reset
    } 2>'' 1>''

    " Reset QoS"; . {
      ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -recurse -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" "*" -force -ea 0
      rp "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableUserTOSSetting -force -ea 0
      ri "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -recurse -force -ea 0
      "ActiveStore","$env:computername","GPO:$env:computername" |foreach {
        Get-NetQosPolicy -PolicyStore $_ | Remove-NetQosPolicy -Confirm:$False -ea 0 }
      Unregister-ScheduledTask -TaskName 'Bufferbloat' -confirm:$false -ea 0
    } 2>'' 1>''

    " Reset Group Policy"; . {
      pushd "$env:Systemroot\System32\GroupPolicy\Machine"
      if (test-path "$PWD\before.pol") { del "$PWD\Registry.pol" -force -ea 0; ren "$PWD\before.pol" "Registry.pol" -force }
      gpupdate /Target:Computer /force
      popd
    } 2>'' 1>''
  }

  ##  show network configuration
  function ns: { write-host -fore cyan "`nnetsh" @args; $(netsh @args 2>'' | out-string).Trim("`r","`n") } #
  function ps: { write-host -fore cyan "`npowershell" @args; $(powershell @args 2>'' | out-string).Trim("`r","`n") } #
  ns: int ip show interfaces
  ns: int ipv4 show global
  ns: int tcp show supplemental
  ns: int tcp show global
  ns: winsock show autotuning
  ps: Get-NetTCPSetting -SettingName internet
  ps: Get-NetTransportFilter `|ft
  ps: Get-NetAdapterHardwareInfo #`| fl
  ps: Get-SmbClientNetworkInterface
  ps: Get-NetAdapterRSS `|ft
  ps: Get-NetAdapterChecksumOffload
  ps: Get-NetAdapterLso
  ps: Get-NetOffloadGlobalSetting `|fl
  ps: Get-NetQosPolicy -PolicyStore ActiveStore
  gi "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
  gi "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
  if ($PAUSE_FOR_SUMMARY -gt 0) {
    $ws = new-object -ComObject Wscript.Shell; $ws.Popup("$id $do", 0, "Done", 0x0) >''; $ws = $null
  }
}

##  AveYo: elevate
if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -notcontains 'S-1-5-32-544') {
  write-host " '$id' Requesting ADMIN rights.. " -fore Black -back Yellow; sleep 2
  sp HKCU:\Volatile*\* $id ".{$ps} '$($f0-replace"'","''")' '$($cl-replace"'","''")' '$id'" -force -ea 0
  start powershell -args "-nop -c (gp Registry::HKU\S-1-5-21*\Volatile*\*).'$id' | out-string | powershell -nop -c -" -verb runas
} else {. $ps $f0 $cl $id }

} #_press_Enter_if_pasted_in_powershell
