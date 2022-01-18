@echo off& color 07& title reg_own - lean and mean snippet by AveYo, 2018-2022
goto :nfo
    [FEATURES]
    - parameters after key are optional; if -owner if ommited, try to preserve existing
    - enable inherited rights / disable / delete entries with -recurse Inherit / Replace / Delete
    - add -list to show summary even when regedit fails; no low-level registry functions used        
    - can copy-paste snippet directly in powershell (admin) console then use it manually
    [USAGE]
    - First copy-paste reg_own snippet after .bat script content
    - Then call it anywhere (after elevation) to change registry security:
      call :reg_own "key" -recurse Replace -user S-1-5-32-545 -owner S-1-1-0 -acc Allow -perm FullControl
:nfo

:::::::::::::::::::::::::
:: .bat script content ::
:::::::::::::::::::::::::

:::: Define TI sid (TrustedInstaller)
for /f "tokens=3" %%a in ('sc.exe showsid TrustedInstaller') do set TI=%%a >nul

:::: Define USER sid before asking for elevation since it gets replaced for limited accounts
if "%USER%"=="" for /f "tokens=2" %%u in ('whoami /user /fo list') do (set USER=%%u)

:::: Ask for elevation passing USER and any batch arguments
fltmc >nul || (set _=set USER=%USER%^& call "%~f0" %*& powershell -nop -c start cmd -args '/d/x/r',$env:_ -verb runas& exit)

::# lean xp+ color macros by AveYo:  %<%:af " hello "%>>%  &  %<%:cf " w\"or\"ld "%>%   for single \ / " use .%|%\  .%|%/  \"%|%\"
for /f "delims=:" %%s in ('echo;prompt $h$s$h:^|cmd /d') do set "|=%%s"&set ">>=\..\c nul&set /p s=%%s%%s%%s%%s%%s%%s%%s<nul&popd"
set "<=pushd "%public%"&2>nul findstr /c:\ /a" &set ">=%>>%&echo;" &set "|=%|:~0,1%" &set /p s=\<nul>"%public%\c"

:: Setup a test key
reg delete HKLM\SOFTWARE\REG_OWN /f >nul 2>nul& reg add HKLM\SOFTWARE\REG_OWN\DEL\ME\NOW /f >nul 2>nul & prompt $E >nul

%<%:af " Allow FullControl from Administrators "%>>% & %<%:f0 " default, just this key "%>%
echo;call :reg_own "HKEY_LOCAL_MACHINE\SOFTWARE\REG_OWN" -list
     call :reg_own "HKEY_LOCAL_MACHINE\SOFTWARE\REG_OWN" -list

%<%:8f " Allow READ from Users "%>>% & %<%:f0 " recursive, enable inheritance [no -list to hide output] "%>%
echo;call :reg_own "HKLM:\SOFTWARE\REG_OWN\DEL" -recurse Inherit -user S-1-5-32-545 -acc Allow -perm ReadKey
     call :reg_own "HKLM:\SOFTWARE\REG_OWN\DEL" -recurse Inherit -user S-1-5-32-545 -acc Allow -perm ReadKey

echo;
%<%:5f " Allow WriteKey from %%USER%% and set owner to SYSTEM "%>>% & %<%:f0 " just this key "%>%
echo;call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -user %%USER%% -owner S-1-5-18 -acc Allow -perm WriteKey -list
     call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -user %USER%   -owner S-1-5-18 -acc Allow -perm WriteKey -list

%<%:cf " Deny changes from Everyone and set owner to TrustedInstaller "%>>% & %<%:f0 " recursive, disable inheritance "%>%
set nochanges="SetValue,Delete,ChangePermissions,TakeOwnership"
echo;call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Replace -user S-1-1-0 -owner %%TI%% -acc Deny -perm %nochanges% -list
     call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Replace -user S-1-1-0 -owner %TI%   -acc Deny -perm %nochanges% -list

echo;
%<%:0e "TO WRITE LOCKED VALUES WHILE TRYING TO PRESERVE EXISTING OWNER AND RIGHTS I RECOMMEND THE FOLLOWING:"%>%

echo;
%<%:e0 "0. DO WHATEVER MODIFICATIONS NEEDED IN THE TARGET REGKEY - SHOULD FAIL NOW "%>%
echo;reg add "HKLM\SOFTWARE\REG_OWN\DEL" /v somevalue /d somedata /f
     reg add "HKLM\SOFTWARE\REG_OWN\DEL" /v somevalue /d somedata /f

echo;
%<%:9e "1. Allow FullControl from Everyone "%>>% & %<%:f0 " recursive, disable inheritance "%>%
echo;call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Replace -user S-1-1-0 -list
     call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Replace -user S-1-1-0 -list

%<%:e0 "2. DO WHATEVER MODIFICATIONS NEEDED IN THE TARGET REGKEY - SHOULD SUCCEED NOW "%>%
echo;reg add "HKLM\SOFTWARE\REG_OWN\DEL" /v somevalue /d somedata /f
     reg add "HKLM\SOFTWARE\REG_OWN\DEL" /v somevalue /d somedata /f

echo;
%<%:9e "3. Remove non-inherited rules from Everyone "%>>% & %<%:f0 " recursive, delete "%>%
echo;call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Delete -user S-1-1-0 -list
     call :reg_own "HKLM\SOFTWARE\REG_OWN\DEL" -recurse Delete -user S-1-1-0 -list

:: Delete test key
reg delete HKLM\SOFTWARE\REG_OWN /f >nul 2>nul

echo;
%<%:bf " Done! "%>%
choice /c EX1T
exit /b

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: .bat script content end - copy-paste reg_own snippet ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

#:reg_own "HKCU\Key" -recurse Inherit / Replace / Delete -user S-1-5-32-545 -owner '' -acc Allow -perm ReadKey
set ^ #=&set "0=%~f0"&set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split'#\:reg_own .*')[1]); # --%% %*&exit/b
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
}; iex "reg_own $(([environment]::get_CommandLine()-split'-[-]%+ ?')[1])" #:reg_own lean & mean snippet by AveYo, 2022.01.15
