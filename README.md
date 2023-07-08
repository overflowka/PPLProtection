# PPLProtection
Protect your process like ntoskrnl.exe

Supports Win10 19H1 - Win11 22H2


Protected Process Light (PPL) technology is used for controlling and protecting running processes and protecting them from infection by malicious code and the potentially harmful effects of other processes.
These processes include:
1. Shutdown / Terminate / Suspend / Freeze / Restart
2. Stream deployment
3. Access to virtual memory
4. Debugging
5. Copying of descriptors
6. Changing the memory working set
7. Changing and receiving information about the current state of the thread 
8. Impersonation of threads (running process threads under a different account)

Compile the project in Release x64, and load the driver with kdmapper.

![image](https://github.com/overflowka/PPLProtection/assets/71901175/25a950b2-ef7b-4586-b195-f8c797a6d48c)
![image](https://user-images.githubusercontent.com/71901175/235199171-18c2e6ac-de35-4d44-85dc-f70499444138.png)
