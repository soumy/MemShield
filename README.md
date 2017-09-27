# MemShield
No more Remote Code Execution

MemShield attempts to drastically minimize the scope of remote code execution vulnerabilities that can be exploited. It achieves this by not allowing the creation of an executable memory region where a shellcode can be placed.
An attempt to exploit a remote code execution vulnerability on an application protected with MemShield would only result in crash of the protected process which is much better than getting owned.

MemShield is a windows dll which once loaded would enforce:
1) No memory page in a process can have execute permissions which does not belong to a loaded image.
2) Inside a loaded image, enforce "write xor execute" page permissions.
3) Runtime creation of executable pages would not be allowed.

Obviously with the above memory permissions a number of applications which has JIT compilation or has other requirement for READ_WRITE_EXECUTE memory would not work.
But that should not stop us from running MemShield on a lot of server applications. The idea is to make the server services immune to RCE.

Help needed:
1) Developers
2) Testers 

Install instructions for all Windows versions starting from Windows XP, except Windows 10:
1) Download the latest release and extract the archive. Perform the following steps on the system where you want the deployment.

2) Open command prompt(cmd.exe) as local Administrator and change directory to the folder where you extracted the release archive.

3) Execute SDBCreate.exe with the filename of the executable that you want to protect.
   For example:  SDBCreate.exe mysqld.exe 

4) Two .SDB files would get created on the current directory. MemShield32.sdb and MemShield64.sdb.

5) Execute sdbinst MemShield32.sdb
   On 64 bit OS additionally execute sdbinst MemShield64.sdb

6) Copy MemShield32.dll into C:\Windows\AppPatch folder.
   On 64 bit OS additionally copy MemShield64.dll into C:\Windows\AppPatch\apppatch64 folder.

Install instructions for Windows 10 32 bit:
1) Download the latest release and extract the archive. Perform the following steps on the system where you want the deployment.

2) Download Windows ADK for Windows 10 from:
   http://go.microsoft.com/fwlink/p/?LinkId=526740

3) Install "Application Compatibility Tools" from the ADK setup.

4) Run "Compatibility Administrator (32-bit)" from start menu.

5) Click "Fix" on the toolbar, give name of the program to protect and browse to select the program file and click "Next".

6) Nothing to do on the "Compatibility Modes" so again click "Next".

7) On the "Compatibility Fixes" select the checkbox next to "InjectDll" and click on "Parameters".

8) Put the complete path to the MemShield32.dll file into the "Command line". Type "MemShield" on "Module name" and click "Add".

9) Click "Unselect all" on Matching information and click Finish.

Install instructions for Windows 10 64 bit:
I don't have an easy method to load the MemShield64.dll into a process in Windows 10 64 bit. I don't want to suggest dll injection hacks.
Need suggestions here.
