@(set "0=%~f0"^)#) & powershell -nop -c "`i`e`x([io.file]::ReadAllText($env:0))" & exit /b

## Toggle Def`ender, AveYo 2023.08.06 - now more lean and mean
## for those scenarios where preventing random interference is needed - only works after Tamp`er Prot`ection is off 
## but ms devs still fake-positive'd the script, while actual tro.jans can neuter the service or even uninstall it regardless..
## just copy-paste into powershell

## the ` sprinkles everywhere are used to keep ps event log clean
if (get-process "msmp`eng" -ea 0) {$YES=6; $Q="Disable"; $NO=7; $V="ON"; $I=0} else {$YES=7; $Q="Enable"; $NO=6; $V="OFF"; $I=16}

## TP check
if ((gp "HKLM:\SOFTWARE\Microsoft\Windows Def`ender\Features" "Tamp`erProtection" -ea 0)."Tamp`erProtection" -eq 0x5) {
  write-host "`n Toggle Def`ender only works after Tamp`er Prot`ection is off in Windows Se`curity settings`n"
  start "windowsd`efender://thr`eatsettings/"
  choice /c EX1T 
  if ((gp "HKLM:\SOFTWARE\Microsoft\Windows Def`ender\Features" "Tamp`erProtection" -ea 0)."Tamp`erProtection" -eq 0x5) {return}
}

## Comment to hide dialog prompt with Yes, No, Cancel (6,7,2)
if ($env:1 -ne 6 -and $env:1 -ne 7) {
  $choice=(new-object -ComObject Wscript.Shell).Popup($Q + " Windows Defen`der?", 0, "Defen`der is: " + $V, 0x1033 + $I)
  if ($choice -eq 2) {break} elseif ($choice -eq 6) {$env:1=$YES} else {$env:1=$NO}
}

## Without the dialog prompt above will toggle automatically
if ($env:1 -ne 6 -and $env:1 -ne 7) { $env:1=$YES }

## Toggle - can press No to Enable or Disable again so there are more variants:
if ( ($NO -eq 7 -and $env:1 -eq 6) -or ($NO -eq 6 -and $env:1 -eq 6) ) {$op='Disable'} 
if ( ($NO -eq 7 -and $env:1 -eq 7) -or ($NO -eq 6 -and $env:1 -eq 7) ) {$op='Enable'}

## RunAsTI mod
function RunAsTI { $id="Def`ender"; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U); $G=whoami /groups 
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+'32', 8214,1,$S, $F[3*$_+2], 1,4)}; $As=0; $TI=$G-like'*1-16-16384*' 
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -nop -c `i`e`x `$env:R; # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"("SetPr`ivilege",42)[0]
 "SeSecurityPr`ivilege","SeTakeOwnershipPr`ivilege","SeBackupPr`ivilege","SeRestorePr`ivilege" |% {$priv.Invoke($null, @("$_",2))}
 ################################################################################################################################ 

 $toggle = @(0,1)[$op -eq 'Disable']; write-host "`n Def`ender $op, please wait...`n"
 $HKLM=[uintptr][uint32]2147483650; $REG_OPTION_NONE=0; $KEY_SET_VALUE=2; $REG_DWORD=4                    
 $K1="Software\Policies\Microsoft\Windows Def`ender"; $K2="Software\Microsoft\Windows Def`ender" 
 
 ## toggling was unreliable due to multiple programs with open handles on these keys
 ## so I went with low-level functions instead! imitators should not use it without a trip to learn-microsoft-com  
 function ToggleDef ([byte[]]$d0,[byte[]]$d1) {
   $rok1=($HKLM, $K1, $REG_OPTION_NONE, $KEY_SET_VALUE, ($HKLM -as $D[9])); F 'RegOpenKeyEx' $rok1; $rsv1=$rok1[4]; #$rsv1
   $rok2=($HKLM, $K2, $REG_OPTION_NONE, $KEY_SET_VALUE, ($HKLM -as $D[9])); F 'RegOpenKeyEx' $rok2; $rsv2=$rok2[4]; #$rsv2
   $rsv1,$rsv2 |% { 
     F 'RegSetValueEx' @($_[0], "ServiceK`eepAlive", 0, $REG_DWORD, $d0, 4)
     F 'RegSetValueEx' @($_[0], "PreviousR`unningMode", 0, $REG_DWORD, $d0, 4)
     F 'RegSetValueEx' @($_[0], "IsServic`eRunning", 0, $REG_DWORD, $d0, 4)
     F 'RegSetValueEx' @($_[0], "DisableAntiSp`yware", 0, $REG_DWORD, $d1, 4)
     F 'RegSetValueEx' @($_[0], "DisableAntiV`irus", 0, $REG_DWORD, $d1, 4)
     F 'RegSetValueEx' @($_[0], "Pass`iveMode", 0, $REG_DWORD, $d1, 4)
   }
   F 'RegFlushKey' @($rsv1); F 'RegFlushKey' @($rsv2); sleep 5; F 'RegCloseKey' @($rsv1); F 'RegCloseKey' @($rsv2)
   $rok1=$null; $rok2=$null; $rsv1=$null; $rsv2=$null
 }

 stop-service "ws`csvc"
 kill -name "mp`cmdrun" -force -ea 0 
 ToggleDef 0 $toggle

 pushd "$env:ProgramFiles\Windows Def`ender"
 start -wait "mp`cmdrun.exe" -args "-${op}S`ervice -HighPriority"
  
 while (get-process -name "mp`cmdrun" -ea 0) {sleep 1}
 $wait=@(3,15)[$op -eq 'Disable']
 while ((get-process -name "msmp`eng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1; write-host "`r $wait" -nonew}
 write-host "    "

 ## Comment to not clear per-user toggle notifications
 gi "Registry::HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion" |% {
   $n1=join-path $_ "Notifications\Settings\Windows.SystemToast.Securit`yAndMaintenance"
   ni $n1 -ea 0|out-null; ri $n1.replace("Settings","Current") -recurse -force -ea 0
   if ($op -eq 'Disable') {reg add "$n1" /f /v Enabled /d 0 /t reg_dword >$null} else {reg delete "$n1" /f /v Enabled >$null 2>&1}  
 }

 ## Comment to keep old scan history
 if ($op -eq 'Disable') {del "$env:ProgramData\Microsoft\Windows Def`ender\S`cans\mp`enginedb.db" -force -ea 0}  
 if ($op -eq 'Disable') {del "$env:ProgramData\Microsoft\Windows Def`ender\S`cans\History\S`ervice" -recurse -force -ea 0}

 ToggleDef 0 $toggle
 if ($toggle -eq 0) {start-service "windef`end" -ea 0}
 start-service "ws`csvc"
 
 ################################################################################################################################
'@; $V='';'op','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
} # lean & mean snippet by AveYo, 2023.08.06

RunAsTI
return
