@(echo off% <#%) &title Toggle Defender, AveYo 2021-08-02
set "0=%~f0"&set 1=%*&powershell -nop -win 1 -c iex ([io.file]::ReadAllText($env:0)) &exit/b ||#>)[1]
## Changelog: also toggle store, chredge smartscreen + pua; prevent ui lockdown; unblock exe in chredge 
sp 'HKCU:\Volatile Environment' 'ToggleDefender' @'
if ($(sc.exe qc windefend) -like '*TOGGLE*') {$TOGGLE=7;$KEEP=6;$A='Enable';$S='OFF'}else{$TOGGLE=6;$KEEP=7;$A='Disable';$S='ON'}

## Comment to hide dialog prompt with Yes, No, Cancel (6,7,2)
if ($env:1 -ne 6 -and $env:1 -ne 7) {
  $choice=(new-object -ComObject Wscript.Shell).Popup($A + ' Windows Defender?', 0, 'Defender is: ' + $S, 51)
  if ($choice -eq 2) {break} elseif ($choice -eq 6) {$env:1=$TOGGLE} else {$env:1=$KEEP}
}

## Without the dialog prompt above will toggle automatically
if ($env:1 -ne 6 -and $env:1 -ne 7) { $env:1=$TOGGLE }

## Comment to not relaunch systray icon
$L="$env:ProgramFiles\Windows Defender\MSASCuiL.exe"; if (!(test-path $L)) {$L='SecurityHealthSystray'} ; start $L -win 1

## Comment to not hide per-user toggle notifications
$notif='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance'
ni $notif -ea 0|out-null; ri $notif.replace('Settings','Current') -Recurse -Force -ea 0
sp $notif Enabled 0 -Type Dword -Force -ea 0; if ($TOGGLE -eq 7) {rp $notif Enabled -Force -ea 0}

## Cascade elevation
$u=0;$w=whoami /groups;if($w-like'*1-5-32-544*'){$u=1};if($w-like'*1-16-12288*'){$u=2};if($w-like'*1-16-16384*'){$u=3}

## Reload from volatile registry as needed
$script='-nop -win 1 -c & {$AveYo='+"'`r`r"+' A LIMITED ACCOUNT PROTECTS YOU FROM UAC EXPLOITS '+"`r`r'"+';$env:1='+$env:1
$script+=';$k=@();$k+=gp Registry::HKEY_Users\S-1-5-21*\Volatile* ToggleDefender -ea 0;iex($k[0].ToggleDefender)}' 
$cmd='powershell '+$script; $env:__COMPAT_LAYER='Installer' 

## 0: limited-user: must runas / 1: admin-user non-elevated: must runas [built-in lame uac bpass removed] 
if ($u -lt 2) {
  start powershell -args $script -verb runas -win 1; break
}

## 2: admin-user elevated: get ti/system via runasti lean and mean snippet [$window hide:0x0E080600 show:0x0E080610]
if ($u -eq 2) {
  $A=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1);$D=@();0..5|%{$D+=$A."DefineT`ype"('A'+$_,
  1179913,[ValueType])} ;4,5|%{$D+=$D[$_]."MakeB`yRefType"()} ;$I=[Int32];$J="Int`Ptr";$P=$I.module.GetType("System.$J"); $F=@(0)
  $F+=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$P,$P,$P,$I,$I,$I,$I,$I,$I,$I,$I,[Int16],[Int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
  $S=[String]; $9=$D[0]."DefinePInvokeMeth`od"('CreateProcess',"kernel`32",8214,1,$I,@($S,$S,$I,$I,$I,$I,$I,$S,$D[6],$D[7]),1,4)
  1..5|%{$k=$_;$n=1;$F[$_]|%{$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}};$T=@();0..5|%{$T+=$D[$_]."CreateT`ype"();$Z=[uintptr]::size
  nv ('T'+$_)([Activator]::CreateInstance($T[$_]))}; $H=$I.module.GetType("System.Runtime.Interop`Services.Mar`shal");
  $WP=$H."GetMeth`od"("Write$J",[type[]]($J,$J)); $HG=$H."GetMeth`od"("AllocHG`lobal",[type[]]'int32'); $v=$HG.invoke($null,$Z)
  'TrustedInstaller','lsass'|%{if(!$pn){net1 start $_ 2>&1 >$null;$pn=[Diagnostics.Process]::GetProcessesByName($_)[0];}}
  $WP.invoke($null,@($v,$pn.Handle)); $SZ=$H."GetMeth`od"("SizeOf",[type[]]'type'); $T1.f1=131072; $T1.f2=$Z; $T1.f3=$v; $T2.f1=1
  $T2.f2=1;$T2.f3=1;$T2.f4=1;$T2.f6=$T1;$T3.f1=$SZ.invoke($null,$T[4]);$T4.f1=$T3;$T4.f2=$HG.invoke($null,$SZ.invoke($null,$T[2]))
  $H."GetMeth`od"("StructureTo`Ptr",[type[]]($D[2],$J,'boolean')).invoke($null,@(($T2-as $D[2]),$T4.f2,$false));$window=0x0E080600
  $9=$T[0]."GetMeth`od"('CreateProcess').Invoke($null,@($null,$cmd,0,0,0,$window,0,$null,($T4-as $D[4]),($T5-as $D[5]))); break
}

## Cleanup
rp Registry::HKEY_Users\S-1-5-21*\Volatile* ToggleDefender -ea 0

## Create registry paths
$wdp='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
' Security Center\Notifications','\UX Configuration','\MpEngine','\Spynet','\Real-Time Protection' |% {ni ($wdp+$_)-ea 0|out-null}

## Toggle Defender
if ($env:1 -eq 7) {
  ## enable notifications
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications -Force -ea 0
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration' Notification_Suppress -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' Notification_Suppress -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' UILockdown -Force -ea 0
  ## enable shell smartscreen and set to warn
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen -Force -ea 0
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' ShellSmartScreenLevel 'Warn' -Force -ea 0
  ## enable store smartscreen and set to warn
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -ea 0 |% {
    sp $_.PSPath 'EnableWebContentEvaluation' 1 -Type Dword -Force -ea 0
    sp $_.PSPath 'PreventOverride' 0 -Type Dword -Force -ea 0
  }
  ## enable chredge smartscreen + pua
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Edge\SmartScreenEnabled -ea 0 |% {
    sp $_.PSPath '(Default)' 1 -Type Dword -Force -ea 0
  }
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled -ea 0 |% {
    sp $_.PSPath '(Default)' 1 -Type Dword -Force -ea 0
  }
  ## enable legacy edge smartscreen
  ri 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Force -ea 0
  ## enable av
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring -Force -ea 0
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender' DisableAntiSpyware -Force -ea 0
  sc.exe config windefend depend= RpcSs
  net1 start windefend
  kill -Force -Name MpCmdRun -ea 0
  start ($env:ProgramFiles+'\Windows Defender\MpCmdRun.exe') -Arg '-EnableService' -win 1
} else {
  ## disable notifications
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications 1 -Type Dword -ea 0
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration' Notification_Suppress 1 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications 1 -Type Dword -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' Notification_Suppress 1 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' UILockdown 0 -Type Dword -Force -ea 0
  ## disable shell smartscreen and set to warn
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen 0 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' ShellSmartScreenLevel 'Warn' -Force -ea 0
  ## disable store smartscreen and set to warn
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -ea 0 |% {
    sp $_.PSPath 'EnableWebContentEvaluation' 0 -Type Dword -Force -ea 0
    sp $_.PSPath 'PreventOverride' 0 -Type Dword -Force -ea 0
  }
  ## disable chredge smartscreen + pua
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Edge\SmartScreenEnabled -ea 0 |% {
    sp $_.PSPath '(Default)' 0 -Type Dword -Force -ea 0
  }
  gp Registry::HKEY_Users\S-1-5-21*\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled -ea 0 |% {
    sp $_.PSPath '(Default)' 0 -Type Dword -Force -ea 0
  }
  ## disable legacy edge smartscreen
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' EnabledV9 0 -Type Dword -Force -ea 0
  ## disable av
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring 1 -Type Dword -Force
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender' DisableAntiSpyware 1 -Type Dword -Force -ea 0
  net1 stop windefend
  sc.exe config windefend depend= RpcSs-TOGGLE
  kill -Name MpCmdRun -Force -ea 0
  start ($env:ProgramFiles+'\Windows Defender\MpCmdRun.exe') -Arg '-DisableService' -win 1
  del ($env:ProgramData+'\Microsoft\Windows Defender\Scans\mpenginedb.db') -Force -ea 0           ## Commented = keep scan history
  del ($env:ProgramData+'\Microsoft\Windows Defender\Scans\History\Service') -Recurse -Force -ea 0
}

## PERSONAL CONFIGURATION TWEAK - COMMENT OR UNCOMMENT #rp ENTRIES TO TWEAK OR REVERT
#sp $wdp DisableRoutinelyTakingAction 1 -Type Dword -Force -ea 0                        ## Auto Actions off
rp $wdp DisableRoutinelyTakingAction -Force -ea 0                                       ## Auto Actions ON [default]

sp ($wdp+'\MpEngine') MpCloudBlockLevel 2 -Type Dword -Force -ea 0                      ## Cloud blocking level HIGH
#rp ($wdp+'\MpEngine') MpCloudBlockLevel -Force -ea 0                                   ## Cloud blocking level low [default]

sp ($wdp+'\Spynet') SpyNetReporting 2 -Type Dword -Force -ea 0                          ## Cloud protection ADVANCED
#rp ($wdp+'\Spynet') SpyNetReporting -Force -ea 0                                       ## Cloud protection basic [default]

sp ($wdp+'\Spynet') SubmitSamplesConsent 0 -Type Dword -Force -ea 0                     ## Sample Submission ALWAYS-PROMPT
#rp ($wdp+'\Spynet') SubmitSamplesConsent -Force -ea 0                                  ## Sample Submission automatic [default]

#sp ($wdp+'\Real-Time Protection') RealtimeScanDirection 1 -Type Dword -Force -ea 0     ## Scan incoming file only
rp ($wdp+'\Real-Time Protection') RealtimeScanDirection -Force -ea 0                    ## Scan INCOMING + OUTGOING file [default]

#sp $wdp PUAProtection 1 -Type Dword -Force -ea 0                                       ## Potential Unwanted Apps on  [policy]
rp $wdp PUAProtection -Force -ea 0                                                      ## Potential Unwanted Apps off [default]
sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender' PUAProtection 1 -Type Dword -Force -ea 0 ## Potential Unwanted Apps ON  [user]
#rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender' PUAProtection -Force -ea 0              ## Potential Unwanted Apps off [default]

## even with "smartscreen" off you still need to unblock exe to download Firefox (sic) & other programs [F][F][S] microsoft!
$LameEdgeExtBlockWithSmartScreenOff='HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExemptDomainFileTypePairsFromFileTypeDownloadWarnings'
ni $LameEdgeExtBlockWithSmartScreenOff -Force -ea 0|out-null ## add other extensions following the example below (increment 1)
sp $LameEdgeExtBlockWithSmartScreenOff '1' '{"file_extension": "exe", "domains": ["*"]}' -Force -ea 0  

# done!
'@ -Force -ea 0; $k=@();$k+=gp Registry::HKEY_Users\S-1-5-21*\Volatile* ToggleDefender -ea 0;iex($k[0].ToggleDefender)
#-_-# hybrid script, can be pasted directly into powershell console
