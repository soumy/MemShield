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

In very early development stage. Detailed usage guide would be provided once the project is at Alpha stage.

Help needed:
1) Developers
2) Testers 
