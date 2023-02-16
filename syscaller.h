#pragma once
#include <minwindef.h>
#include <memoryapi.h>
#include <vector>

template <typename T>
static inline auto GetBytes(unsigned char* bytes, DWORD offset, size_t custom_size = 0) -> T
{
	if (custom_size == 0)
		custom_size = sizeof(T);

	std::vector<unsigned char>buffer(bytes + offset, bytes + offset + custom_size);

	return *reinterpret_cast<T*>(buffer.data());
}


static inline DWORD RVAToOffset(unsigned char* bytes, DWORD offset, IMAGE_DOS_HEADER dosheader, IMAGE_NT_HEADERS ntheader)
{
	for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER section = GetBytes<IMAGE_SECTION_HEADER>(bytes, dosheader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);

		if (section.VirtualAddress <= offset && offset < (section.VirtualAddress + section.Misc.VirtualSize))
		{
			return offset + (section.PointerToRawData - section.VirtualAddress);
		}
	}

	return 0x0;
}

static inline void* GetSyscallFunction(DWORD SyscallId)
{
	unsigned char id[4];
	memcpy(id, &SyscallId, sizeof(DWORD));

	const unsigned char code[] = {
		// mov rax, gs: [0x60]
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
		0x00, 0x00,

		// mov r10, rcx
		0x4C, 0x8B, 0xD1,

		// mov eax, SyscallId
		0xB8, id[0], id[1], id[2], id[3],

		// syscall
		0x0f, 0x05,

		// retn
		0xC3
	};

	void* exec = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof code);

	return exec;
}

inline void* syscall(PCSTR function)
{
	std::ifstream input("C:\\Windows\\System32\\ntdll.dll", std::ios::binary);

	if (!input) // Can't open ntdll.dll for some reason
		return nullptr;

	std::vector<unsigned char> temp(
		(std::istreambuf_iterator<char>(input)),
		(std::istreambuf_iterator<char>()));

	input.close();
	unsigned char* dllFile = temp.data();

	IMAGE_DOS_HEADER dosheader2 = GetBytes<IMAGE_DOS_HEADER>(dllFile, 0x0);
	IMAGE_NT_HEADERS ntheaders = GetBytes<IMAGE_NT_HEADERS>(dllFile, dosheader2.e_lfanew);
	DWORD exportadr = RVAToOffset(dllFile, ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dosheader2, ntheaders);
	IMAGE_EXPORT_DIRECTORY exports = GetBytes<IMAGE_EXPORT_DIRECTORY>(dllFile, exportadr);

	DWORD offset = 0x0;
	DWORD adrOfNames = RVAToOffset(dllFile, exports.AddressOfNames, dosheader2, ntheaders);
	DWORD adrOfFunctions = RVAToOffset(dllFile, exports.AddressOfFunctions, dosheader2, ntheaders);
	DWORD adrOfOrdinals = RVAToOffset(dllFile, exports.AddressOfNameOrdinals, dosheader2, ntheaders);

	DWORD tempByteOffset = exports.AddressOfNameOrdinals - adrOfOrdinals; // Could be any of the above


	for (DWORD i = 0; i < exports.NumberOfNames; i++)
	{
		offset = 0x0;
		std::vector<unsigned char> tempByteVector;

		DWORD nameAdrs = GetBytes<DWORD>(dllFile, adrOfNames + i * 4);

		while (true)
		{
			BYTE tempByte = dllFile[nameAdrs + offset - tempByteOffset];
			offset++;

			tempByteVector.push_back(tempByte);

			if (tempByte == 0x0) // End of function name
			{
				PCSTR func = (PSTR)tempByteVector.data();

				if (strcmp(func, function) == 0)
				{
					WORD ordTemp = GetBytes<WORD>(dllFile, adrOfOrdinals + i * 2);
					DWORD funcAdrs = GetBytes<DWORD>(dllFile, adrOfFunctions + ordTemp * 4);
					DWORD funcBytes = RVAToOffset(dllFile, funcAdrs, dosheader2, ntheaders);

					// Check for syscall instruction, return nullptr if not found... these offsets should not be hardcoded
					if (dllFile[funcBytes + 18] != 0x0f || dllFile[funcBytes + 19] != 0x05)
						return nullptr;

					DWORD syscallId = GetBytes<DWORD>(dllFile, funcBytes + 4);

					return GetSyscallFunction(syscallId);
				}

				break;
			}
		}
	}

	return nullptr;
}

#define SYSCALL(a) syscall(a)