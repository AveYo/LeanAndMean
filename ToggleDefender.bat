@(set "0=%~f0"^)#) & powershell -nop -c "iex([io.file]::ReadAllText($env:0))" & exit /b

## Toggle Defender, AveYo 2023.08.07
## for users that understand the risk but still need it off to prevent unexpected interference and i/o handicap
## may copy-paste directly into powershell

## Allowed check
if ((gp "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection" -ea 0).TamperProtection -eq 0x5) {
  write-host "`n Toggle Defender only works after turning Tamper Protection off in Windows Security settings`n"
  choice /c EX1T 
  if ((gp "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection" -ea 0).TamperProtection -eq 0x5) {return}
}

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

## RunAsTI mod
function RunAsTI { $id="Defender"; $key="Registry::HKU\S-1-5-21-*\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+="kernel","Creat`eProcess",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), "advapi","RegOp`enKeyEx",($U,$S,$I,$I,$D[9])
 $F+="advapi","RegSetVa`lueEx",($U,$S,$I,$I,[byte[]],$I),"advapi","RegF`lushKey",($U),"advapi","RegC`loseKey",($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 if ([environment]::username -ne "system") { $TI="Trusted`Installer"; start-service $TI -ea 0; $As=get-process -name $TI -ea 0
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $R=@($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F "Creat`eProcess" $R; return}; $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"("SetPr`ivilege",42)[0]
 "SeSecurityPr`ivilege","SeTakeOwnershipPr`ivilege","SeBackupPr`ivilege","SeRestorePr`ivilege" |% {$e.Invoke($null,@("$_",2))}
 ################################################################################################################################ 
 
 ## The ` sprinkles are used to keep ps event log clean, not quote the whole snippet on every run
 $toggle = @(0,1)[$op -eq "Disable"]; write-host "`n $op Defender, please wait...`n"
 $HKLM=[uintptr][uint32]2147483650; $REG_OPTION_NONE=0; $KEY_SET_VALUE=2; $REG_DWORD=4                    
 $K1="Software\Policies\Microsoft\Windows Defender"; $K2="Software\Microsoft\Windows Defender" 
 
 ## Toggling was unreliable due to multiple windows programs with open handles on these keys
 ## so I went with low-level functions instead! do not use them in other scripts without a trip to learn-microsoft-com  
 function ToggleDef ([byte[]]$d0,[byte[]]$d1) {
   $rok1=($HKLM, $K1, $REG_OPTION_NONE, $KEY_SET_VALUE, ($HKLM -as $D[9])); F "RegOp`enKeyEx" $rok1; $rsv1=$rok1[4]; #$rsv1
   $rok2=($HKLM, $K2, $REG_OPTION_NONE, $KEY_SET_VALUE, ($HKLM -as $D[9])); F "RegOp`enKeyEx" $rok2; $rsv2=$rok2[4]; #$rsv2
   $rsv1,$rsv2 |% { 
     F "RegSetVa`lueEx" @($_[0], "ServiceK`eepAlive", 0, $REG_DWORD, $d0, 4)
     F "RegSetVa`lueEx" @($_[0], "Previou`sRunningMode", 0, $REG_DWORD, $d0, 4)
     F "RegSetVa`lueEx" @($_[0], "IsServic`eRunning", 0, $REG_DWORD, $d0, 4)
     F "RegSetVa`lueEx" @($_[0], "DisableAntiSp`yware", 0, $REG_DWORD, $d1, 4)
     F "RegSetVa`lueEx" @($_[0], "DisableAntiV`irus", 0, $REG_DWORD, $d1, 4)
     F "RegSetVa`lueEx" @($_[0], "Passiv`eMode", 0, $REG_DWORD, $d1, 4)
   }
   F "RegF`lushKey" @($rsv1); F "RegF`lushKey" @($rsv2); sleep 5; F "RegC`loseKey" @($rsv1); F "RegC`loseKey" @($rsv2)
   $rok1=$null; $rok2=$null; $rsv1=$null; $rsv2=$null; [GC]::Collect() 
 }

 rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" "Disabled_Old" -force -ea 0
 sp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 -type Dword -force -ea 0
 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 ToggleDef 0 $toggle

 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-${op}Service -HighPriority"

 $wait=@(3,14)[$op -eq "Disable"]
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1; write-host "`r $wait " -nonew}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 if ($op -eq "Disable") {ren MpCmdRun.exe OFFmeansOFF.exe -force -ea 0} else {ren OFFmeansOFF.exe MpCmdRun.exe -force -ea 0}
 
 ## Comment to not clear per-user toggle notifications
 gi "Registry::HKU\S-1-5-21-*\SOFTWARE\Microsoft\Windows\CurrentVersion" |% {
   $n1=join-path $_.PSPath "Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance"
   ni $n1 -force -ea 0|out-null; ri $n1.replace("Settings","Current") -recurse -force -ea 0
   if ($op -eq "Enable") {rp $n1 "Enabled" -force -ea 0} else {sp $n1 "Enabled" 0 -type Dword -force -ea 0}
   ri "HKLM:\SOFTWARE\Microsoft\Windows Security Health\State\Persist" -recurse -force -ea 0 
 }

 ## Comment to keep old scan history
 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ea 0}  
 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ea 0}

 ToggleDef 0 $toggle
 if ($op -eq "Enable") {start-service "windefend" -ea 0}
 start-service "wscsvc" -ea 0 >'' 2>'' 
 if ($op -eq "Enable") {rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled_Old" "Disabled" -force -ea 0}
 
 ################################################################################################################################
'@; $V='';"op","id","key"|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas
} # lean & mean snippet by AveYo, 2023.08.07

RunAsTI
return
