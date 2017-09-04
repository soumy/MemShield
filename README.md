# MemShield
No more Remote Code Execution

MemShield attempts to drastically minimize the scope of remote code vulnerabilities that can be exploited.

In development stage, not ready for use. Detailed installation guide would be provided once the project is at Alpha stage.

MemShield is a windows dll which once loaded it would enforce:
1) No memory page in a process can have execute permissions which does not belong to a loaded image.
2) Inside a loaded image, enforce "write xor execute" page permissions.
3) Runtime creation of executable pages would not be allowed.

Obviously with the above permissions a number of applications which has JIT compilation or has other requirement for READ_WRITE_EXECUTE memory would not work.
But that should not stop us from running MemShield on a lot of server applications. The idea is to make the server services immune to RCE.
