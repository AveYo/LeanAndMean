$host.ui.RawUI.WindowTitle = 'reg_own - lean and mean snippet by AveYo, 2018-2022'
<#
    [FEATURES]
    - parameters after key are optional; if -owner if ommited, try to preserve existing
    - enable inherited rights / disable / delete entries with -recurse Inherit / Replace / Delete
    - add -list to show summary even when regedit fails; no low-level registry functions used        
    - can copy-paste snippet directly in powershell (admin) console then use it manually
    [USAGE]
    - First copy-paste reg_own snippet before .ps1 script content
    - Then call it anywhere (after elevation) to change registry security:
      reg_own "key" -recurse Replace -user S-1-5-32-545 -owner S-1-1-0 -acc Allow -perm FullControl
#>

#########################################################
# copy-paste reg_own snippet before .ps1 script content #
#########################################################

function reg_own { param ( $key, $recurse='', $user='S-1-5-32-544', $owner='', $acc='Allow', $perm='FullControl', [switch]$list )
  $D1=[uri].module.gettype('System.Diagnostics.Process')."GetM`ember"('SetPrivilege',42)[0]; $u=$user; $o=$owner; $p=524288  
  'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$D1.Invoke($null, @("$_",2))}
  $reg=$key-split':?\\',2; $key=$reg-join'\'; $HK=gi -lit Registry::$($reg[0]) -force; $re=$recurse; $in=(1,0)[$re-eq'Inherit']
  $own=$o-eq''; if($own){$o=$u}; $sid=[Security.Principal.SecurityIdentifier]; $w='S-1-1-0',$u,$o |% {new-object $sid($_)}
  $r=($w[0],$p,1,0,0),($w[1],$perm,1,0,$acc) |% {new-object Security.AccessControl.RegistryAccessRule($_)}; function _own($k,$l) {
  $t=$HK.OpenSubKey($k,2,'TakeOwnership'); if($t) { try {$n=$t.GetAccessControl(4)} catch {$n=$HK.GetAccessControl(4)}
  $u=$n.GetOwner($sid); if($own-and $u) {$w[2]=$u}; $n.SetOwner($w[0]); $t.SetAccessControl($n); $d=$HK.GetAccessControl(2)
  $c=$HK.OpenSubKey($k,2,'ChangePermissions'); $b=$c.GetAccessControl(2); $d.RemoveAccessRuleAll($r[1]); $d.ResetAccessRule($r[0])
  $c.SetAccessControl($d); if($re-ne'') {$sk=$HK.OpenSubKey($k).GetSubKeyNames(); foreach($i in $sk) {_own "$k\$i" $false}}
  if($re-ne'') {$b.SetAccessRuleProtection($in,1)}; $b.ResetAccessRule($r[1]); if($re-eq'Delete') {$b.RemoveAccessRuleAll($r[1])} 
  $c.SetAccessControl($b); $b,$n |% {$_.SetOwner($w[2])}; $t.SetAccessControl($n)}; if($l) {return $b|fl} }; _own $reg[1] $list
} # lean & mean snippet by AveYo, 2022.01.15

#######################
# .ps1 script content #
#######################

#### Define TI sid (TrustedInstaller)
$TI = (sc.exe showsid TrustedInstaller)-split': '|?{$_-like'*S-1-*'}

#### Define USER sid before asking for elevation since it gets replaced for limited accounts
if ($null -eq $USER) {$USER = ((whoami /user)-split' ')[-1]}

#### Ask for elevation passing USER
$admin = fltmc; if ($LASTEXITCODE) {
  $arg = "-nop -c `$USER='$USER'; iex((gc '$($MyInvocation.MyCommand.Path-replace'''','''''')')-join'`n')" 
  start powershell -verb runas -args $arg; exit
}

#### Setup a test key
reg delete HKLM\SOFTWARE\REG_OWN /f >$null 2>$null; reg add HKLM\SOFTWARE\REG_OWN\DEL\ME\NOW /f >$null 2>$null; function prompt {}

write-host " Allow FullControl from Administrators " -back 0xa -fore 0xf -nonew
write-host " default, just this key " -back 0xf -fore 0x0
write-host "reg_own 'HKEY_LOCAL_MACHINE\SOFTWARE\REG_OWN' -list"
            reg_own 'HKEY_LOCAL_MACHINE\SOFTWARE\REG_OWN' -list

write-host " Allow READ from Users " -back 0x8 -fore 0xf -nonew
write-host " recursive, enable inheritance [no -list to hide output] " -back 0xf -fore 0x0
write-host "reg_own 'HKLM:\SOFTWARE\REG_OWN\DEL' -recurse Inherit -user S-1-5-32-545 -acc Allow -perm ReadKey"
            reg_own 'HKLM:\SOFTWARE\REG_OWN\DEL' -recurse Inherit -user S-1-5-32-545 -acc Allow -perm ReadKey

write-host
write-host " Allow WriteKey from `$USER and set owner to SYSTEM " -back 0xd -fore 0xf -nonew
write-host " just this key " -back 0xf -fore 0x0
write-host "reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -user `$USER -owner S-1-5-18 -acc Allow -perm WriteKey -list"
            reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -user  $USER -owner S-1-5-18 -acc Allow -perm WriteKey -list

write-host " Deny changes from Everyone and set owner to TrustedInstaller " -back 0xc -fore 0xf -nonew
write-host " recursive, disable inheritance " -back 0xf -fore 0x0
$nochanges = "SetValue,Delete,ChangePermissions,TakeOwnership"
write-host "reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Replace -user S-1-1-0 -owner `$TI -acc Deny -perm `$nochanges -list"
            reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Replace -user S-1-1-0 -owner  $TI -acc Deny -perm  $nochanges -list

write-host
write-host "TO WRITE LOCKED VALUES WHILE TRYING TO PRESERVE EXISTING OWNER AND RIGHTS I RECOMMEND THE FOLLOWING:" -back 0x0 -fore 0xe

write-host
write-host "0. DO WHATEVER MODIFICATIONS NEEDED IN THE TARGET REGKEY - SHOULD FAIL NOW " -back 0xe -fore 0x0
write-host "reg add 'HKLM\SOFTWARE\REG_OWN\DEL' /v somevalue /d somedata /f"
            reg add 'HKLM\SOFTWARE\REG_OWN\DEL' /v somevalue /d somedata /f

write-host
write-host "1. Allow FullControl from Everyone " -back 0x9 -fore 0xe -nonew
write-host " recursive, disable inheritance " -back 0xf -fore 0x0
write-host "reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Replace -user S-1-1-0 -list"
            reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Replace -user S-1-1-0 -list

write-host "2. DO WHATEVER MODIFICATIONS NEEDED IN THE TARGET REGKEY - SHOULD SUCCEED NOW " -back 0xe -fore 0x0
write-host "reg add 'HKLM\SOFTWARE\REG_OWN\DEL' /v somevalue /d somedata /f"
            reg add 'HKLM\SOFTWARE\REG_OWN\DEL' /v somevalue /d somedata /f

write-host
write-host "3. Remove non-inherited rules from Everyone " -back 0x9 -fore 0xe -nonew
write-host " recursive, delete " -back 0xf -fore 0x0
write-host "reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Delete -user S-1-1-0 -list"
            reg_own 'HKLM\SOFTWARE\REG_OWN\DEL' -recurse Delete -user S-1-1-0 -list

#### Delete test key
reg delete HKLM\SOFTWARE\REG_OWN /f >$null 2>$null

write-host
write-host " Done! "
choice /c EX1T
return
