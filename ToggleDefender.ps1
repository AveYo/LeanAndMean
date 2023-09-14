@(set "0=%~f0"^)#) & powershell -nop -c "iex([io.file]::ReadAllText($env:0))" & exit /b

## Toggle Defender, AveYo 2023.09.13
## for users that understand the risk but still need it off to prevent unexpected interference and i/o handicap
## may copy-paste directly into powershell

$ENABLE_TAMPER_PROTECTION = 0    <#  1 script re-enables Tamper Protection   0 skip  #>
$TOGGLE_SMARTSCREENFILTER = 1    <#  1 script toggles SmartScreen as well    0 skip  #>

## Allowed check
$wait = 20; while ((gp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' 'TamperProtection' -ea 0).TamperProtection -ne 0x4) {
  if ($wait -eq 20) {echo "`n Toggle Defender only works after turning Tamper Protection off in Windows Security settings`n"}
  if ($wait -eq 16) {if ($ENABLE_TAMPER_PROTECTION -ne 0) {start 'windowsdefender://threatsettings/'}}
  if ($wait -lt 0) {kill -name ApplicationFrameHost -force -ea 0; return}
  write-host "`r $wait " -nonew; sleep 1; $wait--
}
write-host; kill -name ApplicationFrameHost -force -ea 0 

## Service check
if (get-process "MsMpEng" -ea 0) {$YES=6; $Q="Disable"; $NO=7; $V="ON"; $I=0} else {$YES=7; $Q="Enable"; $NO=6; $V="OFF"; $I=16}

## Comment to hide dialog prompt with Yes, No, Cancel (6,7,2)
if ($env:1 -ne 6 -and $env:1 -ne 7) {
  $choice=(new-object -ComObject Wscript.Shell).Popup($Q + " Windows Defender?", 0, "Defender service is: " + $V, 0x1033 + $I)
  if ($choice -eq 2) {break} elseif ($choice -eq 6) {$env:1=$YES} else {$env:1=$NO}
}

## Without the dialog prompt above would toggle automatically
if ($env:1 -ne 6 -and $env:1 -ne 7) {$env:1=$YES}

## Toggle - can press No to Enable or Disable again so there are more variants:
if ( ($NO -eq 7 -and $env:1 -eq 6) -or ($NO -eq 6 -and $env:1 -eq 6) ) {$op="Disable"} 
if ( ($NO -eq 7 -and $env:1 -eq 7) -or ($NO -eq 6 -and $env:1 -eq 7) ) {$op="Enable"}

## pass script options
$O1 = $ENABLE_TAMPER_PROTECTION; $O2 = $TOGGLE_SMARTSCREENFILTER

## RunAsTI mod
function RunAsTI { $id="Defender"; $key='Registry::HKU\S-1-5-21-*\Volatile Environment'; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 if ([environment]::username -ne "system") { $TI="Trusted`Installer"; start-service $TI -ea 0; $As=get-process -name $TI -ea 0
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $R=@($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $R; return}; $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$e.Invoke($null,@("$_",2))}
 ## Toggling was unreliable due to multiple windows programs with open handles on these keys
 ## so went with low-level functions instead! do not use them in other scripts without a trip to learn-microsoft-com  
 function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE=4, $REG_ACCESS=2, $REG_OPTION=0) {
   $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]));  F "RegOpenKeyEx" $rok; $rsv = $rok[4]
   $values |% {$i = 0} { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
   F "RegFlushKey" @($rsv); F "RegCloseKey" @($rsv); $rok = $null; $rsv = $null;
 }  
 ## The ` sprinkles are used to keep ps event log clean, not quote the whole snippet on every run
 ################################################################################################################################ 
 
 ## get script options
 $toggle = @(0,1)[$op -eq "Disable"]; $toggle_rev = @(0,1)[$op -eq "Enable"]; write-host "`n $op Defender, please wait...`n"
 $ENABLE_TAMPER_PROTECTION = $O1; $TOGGLE_SMARTSCREENFILTER = $O2

 rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" "Disabled_Old" -force -ea 0
 sp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 -type Dword -force -ea 0
 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 
 $HKLM = [uintptr][uint32]2147483650; $HKU = [uintptr][uint32]2147483651 
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1
 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-${op}Service -HighPriority"
 $wait=@(3,14)[$op -eq "Disable"]
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1; write-host "`r $wait " -nonew}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 if ($op -eq "Disable") {ren MpCmdRun.exe OFFmeansOFF.exe -force -ea 0} else {ren OFFmeansOFF.exe MpCmdRun.exe -force -ea 0}
 
 ## Comment to not clear per-user toggle notifications
 gi "Registry::HKU\S-1-5-21-*\Software\Microsoft\Windows\CurrentVersion" |% {
   $n1=join-path $_.PSPath "Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance"
   ni $n1 -force -ea 0|out-null; ri $n1.replace("Settings","Current") -recurse -force -ea 0
   if ($op -eq "Enable") {rp $n1 "Enabled" -force -ea 0} else {sp $n1 "Enabled" 0 -type Dword -force -ea 0}
   ri "HKLM:\Software\Microsoft\Windows Security Health\State\Persist" -recurse -force -ea 0 
 }

 ## Comment to keep old scan history
 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ea 0}  
 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ea 0}

 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

 ## when toggling Defender, also toggle SmartScreen - set to 0 at top of the script to skip it
 if ($TOGGLE_SMARTSCREENFILTER -ne 0) {
   sp "HKLM:\CurrentControlSet\Control\CI\Policy" 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ea 0
   sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" 'SmartScreenEnabled' @('Off','Warn')[$toggle -eq 0] -force -ea 0 
   gi Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 |% {
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $toggle_rev -type Dword -force -ea 0
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $toggle_rev -type Dword -force -ea 0
     ni "$($_.PSPath)\Edge\SmartScreenEnabled" -ea 0 > ''
     sp "$($_.PSPath)\Edge\SmartScreenEnabled" "(Default)" $toggle_rev
   }
   if ($toggle_rev -eq 0) {kill -name smartscreen -force -ea 0}
 }
 
 ## when re-enabling Defender, also re-enable Tamper Protection - annoying but safer - set to 0 at top of the script to skip it
 if ($ENABLE_TAMPER_PROTECTION -ne 0 -and $op -eq "Enable") {
   RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender\Features" ("TamperProtection","TamperProtectionSource") (1,5)
 }
 
 if ($op -eq "Enable") {start-service "windefend" -ea 0}
 start-service "wscsvc" -ea 0 >'' 2>'' 
 if ($op -eq "Enable") {rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled_Old" "Disabled" -force -ea 0}
 
 ################################################################################################################################
'@; $V='';"op","id","key","O1","O2"|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $V,$code -type 7 -force -ea 0
 start powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas
} # lean & mean snippet by AveYo, 2023.09.05

RunAsTI
return
