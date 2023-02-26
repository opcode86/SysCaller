# SysCaller
This project aims to simplify the usage of direct syscalls. It achieves this by looking through the export section of ``ntdll.dll`` for the given function and tries to locate its syscall ID. If the syscall ID is found it maps shellcode that executes the syscall into memory and returns its address.

----
## Functions

``SYSCALL_X64(FunctionName)``<br>
``SYSCALL_X86(FunctionName, ReturnValueType, ArgumentTypes ...)``<br>
Looks through the ``ntdll.dll`` file on disk for the syscall id. This function does not map the file into memory.

``SYSCALL_MEM_X64(FunctionName)``<br>
``SYSCALL_MEM_X86(FunctionName, ReturnValueType, ArgumentTypes ...)``<br>
Looks through the already mapped ``ntdll.dll`` in memory for the syscall id.

----
## Usage
Include the ``syscaller.h`` file in your project. Keep in mind that you can also use the ``SYSCALL`` and ``SYSCALL_MEM`` macros that are dependant on your current Solution Platform.

Example using ``NtQuerySystemInformation`` for x64:
```cpp
#include <windows.h>
#include "syscaller.h"

using f_NtQuerySystemInformation = NTSTATUS(__stdcall*)(
	_In_        SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_       PVOID SystemInformation,
	_In_        ULONG SystemInformationLength,
	_Out_opt_   PULONG ReturnLength
	);

int main()
{
    auto NtQuerySystemInformation = (f_NtQuerySystemInformation)SYSCALL_X64("NtQuerySystemInformation");

    if (NtQuerySystemInformation == nullptr)
        return 0;

    // You can now call NtQuerySystemInformation as if it was any other function.
    BYTE* outputBuffer = NULL;
    ULONG length = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, outputBuffer, length, &length);

    return 0;
}
```

Example using ``NtQuerySystemInformation`` for x86:
```cpp
#include <windows.h>
#include "syscaller.h"

int main()
{
    auto NtQuerySystemInformation = SYSCALL_X86("NtQuerySystemInformation", NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    BYTE* outputBuffer = NULL;
    ULONG length = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, outputBuffer, length, &length);

    return 0;
}
```
----
## OBS!
This project is still under development and needs testing. It has only been tested with a handful of functions so feel free to open an issue if something does not work as should.