# SysCaller
This project aims to simplify the usage of direct syscalls. It achieves this by looking through the export section of ``ntdll.dll`` for the given function and tries to locate its syscall ID. If the syscall ID is found it maps shellcode that executes the syscall into memory and returns its address.

``SYSCALL(FunctionName)`` - Looks through the ``ntdll.dll`` file on disk for the syscall id. This function does not map the file into memory.

``SYSCALL_MEM(FunctionName)`` - Looks through the already mapped ``ntdll.dll`` in memory for the syscall id.

## Usage
Include the ``syscaller.h`` file in your project. You can then call the ``SYSCALL`` macro as shown below.

Example using ``NtQuerySystemInformation``:
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
    auto NtQuerySystemInformation = (f_NtQuerySystemInformation)SYSCALL("NtQuerySystemInformation");

    if(NtQuerySystemInformation == nullptr)
        return 0;

    // You can now call NtQuerySystemInformation as if it was any other function.
    BYTE* outputBuffer = NULL;
    ULONG length = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, outputBuffer, length, &length);

    // ...

    return 0;
}
```

## OBS!
This project is still under development and needs testing. It is currently only tested for x64 and a handful of functions so feel free to open an issue if something does not work as should.