### RunAsTI - lean and mean snippet by AveYo, 2018-2021

#### Usage video:
[![Usage video](https://img.youtube.com/vi/akZNitqkNz0/0.jpg)](https://youtu.be/akZNitqkNz0)

##### RunAsTI.bat
```bat
@(set `" <#=")& echo off& title RunAsTI - lean and mean snippet by AveYo, 2018-2021

:: can use custom args: cmdline with %* [opens "C:\" if empty]; folder/program/oneliners like: cmd /c "whoami & timeout 7"
call :RunAsTI %*

:: add Send to - RunAsTI right-click menu entry to launch files and folders as TI via explorer [optional]
set "0=%~f0"& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':SendTo\:.*')[1])& goto :SendTo:
$SendTo=[Environment]::GetFolderPath('ApplicationData')+'\Microsoft\Windows\SendTo\RunAsTI.bat'; $enc=[Text.Encoding]::UTF8
if ($env:0 -and !(test-path -lit $SendTo)) {[IO.File]::WriteAllLines($SendTo, [io.file]::ReadAllLines($env:0,$enc))}
:SendTo:

EXIT/b ::batch section done

:: ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
#:: [info] to integrate in .bat files, add RunAsTI snippet on bottom and this line before main code
whoami|findstr /i /c:"nt authority\system" >nul || ( call :RunAsTI "%~f0" %* & exit/b )

#:: [info] to integrate in .ps1 files, add RunAsTI snippet and this line on bottom and wrap main code as $main = { code }
if ((whoami)-ne"nt authority\system") {RunAsTI "powershell -file ""$($MyInvocation.MyCommand.Path)"" $args";return}; & $main $args

#:: [info] hybrid script, can paste whole text in powershell to execute, or just the function to do RunAsTI "somecmd"
:: ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~#>)

#:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
```

- scripting of file management or registry editing without altering permissions, with innovative HKCU load
- no external tools needed! still works on win7 powershell 2.0; just 18 - 28 lines in intelligible plain-text 
- adds a **Send to** - **RunAsTI** right-click menu entry to launch files and folders as TI via explorer
- can paste whole text in powershell to open C:\ as TI (def) - or just function {..}; `RunAsTI "somecmd"`

#### Variants:

<details>
<summary>#1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load</summary>

```ps1
#:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
```
</details>

<details>
<summary>#2 snippet to run as TI/System, with /high priority and /priv ownership</summary>

```ps1
#:RunAsTI: #2 snippet to run as TI/System, with /high priority and /priv ownership
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[String]; $9=$D[0]."DefinePInvokeMeth`od"("CreateProcess","kernel`32",8214,1,$I,@($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),1,4)
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 if (!$cmd) {$cmd='cmd'}; start cmd -args ("/q/x/d/r title $id && start `"$id`" /high",$cmd) -win 1} # AveYo 2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
```
</details>

<details>
<summary>#3 snippet to run as TI/System, with defaults</summary>

```ps1
#:RunAsTI: #3 snippet to run as TI/System, with defaults
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[String]; $9=$D[0]."DefinePInvokeMeth`od"("CreateProcess","kernel`32",8214,1,$I,@($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),1,4)
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080610
 if (!$cmd) {$cmd='cmd'}; $out=@($null,$cmd,0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out}
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
```
</details>

#### Integration in .bat and .ps1 scripts:

<details>
<summary>[info] before integration.bat</summary>

```bat
@echo off & title TEST

:: setup
set "key=HKLM\SOFTWARE\Classes\AppID\{0868DC9B-D9A2-4f64-9362-133CEA201299}"
powershell -nop -c "(get-acl '%key:HKLM=HKLM:%').AccessToString"
reg query "%key%" /v RunAs

:: modify
reg add "%key%" /v RunAs /d "TEST-%~1-TEST" /f

:: result
reg query "%key%" /v RunAs

:: restore
reg add "%key%" /v RunAs /d "Interactive User" /f >nul 2>&1

:: done
choice /c EX1T
exit
```

</details>
<details><summary>[info] after integration.bat</summary>

```bat
@echo off & title TEST

:: [info] to integrate in .bat files, add this line before main code then RunAsTI snippet on bottom
whoami|findstr /i /c:"nt authority\system" >nul || ( call :RunAsTI "%~f0" %* & exit/b )

:: setup
set "key=HKLM\SOFTWARE\Classes\AppID\{0868DC9B-D9A2-4f64-9362-133CEA201299}"
powershell -nop -c "(get-acl '%key:HKLM=HKLM:%').AccessToString"
reg query "%key%" /v RunAs

:: modify
reg add "%key%" /v RunAs /d "TEST-%~1-TEST" /f

:: result
reg query "%key%" /v RunAs

:: restore
reg add "%key%" /v RunAs /d "Interactive User" /f >nul 2>&1

:: done
choice /c EX1T
exit

#:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
```
</details>
<details><summary>[info] before integration.ps1</summary>

```ps1
$host.ui.rawui.windowtitle = “TEST"

# setup
  $key = 'HKLM:\SOFTWARE\Classes\AppID\{0868DC9B-D9A2-4f64-9362-133CEA201299}'
  (get-acl $key).AccessToString
  gp $key RunAs

# modify
  sp $key RunAs "TEST-$($args[0])-TEST" -force

# result
  gp $key RunAs

# restore
  sp $key RunAs "Interactive User" -force >$null 2>&1

# done
  choice /c EX1T
  return
```
</details>
<details><summary>[info] after integration.ps1</summary>

```ps1
$main = { $host.ui.rawui.windowtitle = “TEST"

# setup
  $key = 'HKLM:\SOFTWARE\Classes\AppID\{0868DC9B-D9A2-4f64-9362-133CEA201299}'
  (get-acl $key).AccessToString
  gp $key RunAs

# modify
  sp $key RunAs "TEST-$($args[0])-TEST" -force

# result
  gp $key RunAs

# restore
  sp $key RunAs "Interactive User" -force >$null 2>&1

# done
  choice /c EX1T
  return
}

#:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>

#:: [info] to integrate in .ps1 files, wrap main code as $main={code} then add RunAsTI function and this line on bottom
if ((whoami)-ne'nt authority\system') {RunAsTI "powershell -file ""$($MyInvocation.MyCommand.Path)"" $args";return}; & $main $args
```
</details>

#### Q & A:
*Q: what is the deal with the back\`quotes?*  
A: to silence lame powershell keyword-based event-log warnings that include the whole snippet and slows down processing  
*Q: pretty sure reflection is used, single-letter vars for types, then.. any hints about those magic constants and arrays?*  
A: $Ai instance of $T[i] type of $D[i] structure of $DF[i] fields; $D[4] StartupInfoEx, $D[3] StartupInfo, $D[2] lpAttribute..  
$D[0] for pinvoke definitions; numbers mostly calling flags or premade struct sizes; check microsoft docs ^,^  




### ToggleDefender - lean and mean snippet by AveYo, 2018-2021

##### ToggleDefender.bat (or .ps1) (or copy-paste in powershell console)
```bat
@(echo off% <#%) &title Toggle Defender, AveYo 2021-08-01
set "0=%~f0"&set 1=%*&powershell -nop -win 1 -c iex ([io.file]::ReadAllText($env:0)) &exit/b ||#>)[1]
## Changelog: always-notify uac bpass for admin accounts removed [microsoft still not fully fixed it as proven by previous script]
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
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications -Force -ea 0
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration' Notification_Suppress -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' Notification_Suppress -Force -ea 0
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen -Force -ea 0
  rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware -Force -ea 0
  rp 'HKLM:\SOFTWARE\Microsoft\Windows Defender' DisableAntiSpyware -Force -ea 0
  sc.exe config windefend depend= RpcSs
  net1 start windefend
  kill -Force -Name MpCmdRun -ea 0
  start ($env:ProgramFiles+'\Windows Defender\MpCmdRun.exe') -Arg '-EnableService' -win 1
} else {
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications 1 -Type Dword -ea 0
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration' Notification_Suppress 1 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' DisableNotifications 1 -Type Dword -ea 0
  sp 'HKLM:\SOFTWARE\Microsoft\Windows Defender\UX Configuration' Notification_Suppress 1 -Type Dword -Force -ea 0
  sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen 0 -Type Dword -Force -ea 0
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
#sp $wdp DisableRoutinelyTakingAction 1 -Type Dword -Force -ea 0                      ## Auto Actions off
rp $wdp DisableRoutinelyTakingAction -Force -ea 0                                     ## Auto Actions ON [default]
sp $wdp PUAProtection 1 -Type Dword -Force -ea 0                                      ## Potential Unwanted Apps ON
#rp $wdp PUAProtection -Force -ea 0                                                   ## Potential Unwanted Apps off [default]
sp ($wdp+'\MpEngine') MpCloudBlockLevel 2 -Type Dword -Force -ea 0                    ## Cloud blocking level HIGH
#rp ($wdp+'\MpEngine') MpCloudBlockLevel -Force -ea 0                                 ## Cloud blocking level low [default]
sp ($wdp+'\Spynet') SpyNetReporting 2 -Type Dword -Force -ea 0                        ## Cloud protection ADVANCED
#rp ($wdp+'\Spynet') SpyNetReporting -Force -ea 0                                     ## Cloud protection basic [default]
sp ($wdp+'\Spynet') SubmitSamplesConsent 0 -Type Dword -Force -ea 0                   ## Sample Submission ALWAYS-PROMPT
#rp ($wdp+'\Spynet') SubmitSamplesConsent -Force -ea 0                                ## Sample Submission automatic [default]
#sp ($wdp+'\Real-Time Protection') RealtimeScanDirection 1 -Type Dword -Force -ea 0   ## Scan incoming file only
rp ($wdp+'\Real-Time Protection') RealtimeScanDirection -Force -ea 0                  ## Scan INCOMING and OUTGOING file [default]

# done!
'@ -Force -ea 0; $k=@();$k+=gp Registry::HKEY_Users\S-1-5-21*\Volatile* ToggleDefender -ea 0;iex($k[0].ToggleDefender)
#-_-# hybrid script, can be pasted directly into powershell console
```
