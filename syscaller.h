#pragma once
#include <memoryapi.h>
#include <vector>

//
// Helper functions
//

template <typename T>
static inline auto GetBytes(unsigned char* bytes, DWORD offset, size_t custom_size = 0) -> T
{
	if (custom_size == 0)
		custom_size = sizeof(T);

	std::vector<unsigned char>buffer(bytes + offset, bytes + offset + custom_size);

	return *reinterpret_cast<T*>(buffer.data());
}


static DWORD RVAToOffset(unsigned char* bytes, DWORD offset, IMAGE_DOS_HEADER dosheader, IMAGE_NT_HEADERS ntheader)
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

inline static WORD GetSyscallIdMem(BYTE* bytes)
{
	DWORD offset = 0x0;



	while (true)
	{
		if (offset >= 0x17) // 0x20 - 0x08 - 0x01
			break;

		if (
			bytes[offset] == 0x4c &&
			bytes[offset + 1] == 0x8b &&
			bytes[offset + 2] == 0xd1 &&
			bytes[offset + 3] == 0xb8)
		{
			unsigned char id[2] = { bytes[offset + 4], bytes[offset + 5] };
			return *reinterpret_cast<WORD*>(id);
		}

		offset++;
	}

	return 0x0;
}

static inline void* GetSyscallFunction(WORD SyscallId)
{
	BYTE id[2];
	memcpy(id, &SyscallId, sizeof(WORD));

	const BYTE code[] = {
		// mov rax, gs: [0x60]
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
		0x00, 0x00,

		// mov r10, rcx
		0x4C, 0x8B, 0xD1,

		// mov eax, SyscallId
		0xB8, id[0], id[1], 0x00, 0x00,

		// syscall
		0x0f, 0x05,

		// retn
		0xC3
	};

	void* exec = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof code);

	return exec;
}

// Helper function to check if offset differs from RVA, if they are the same something went wrong...
static inline bool ValidateOffset(DWORD RVA, DWORD offset)
{
	return !(RVA == offset);
}

//
// Main functions
//

inline void* syscall(PCSTR function)
{
	std::ifstream input("C:\\Windows\\System32\\ntdll.dll", std::ios::binary);

	if (!input) // Can't open ntdll.dll for some reason
		return nullptr;

	std::vector<BYTE> temp(
		(std::istreambuf_iterator<char>(input)),
		(std::istreambuf_iterator<char>()));

	input.close();
	BYTE* dllFile = temp.data();

	IMAGE_DOS_HEADER dosheader2 = GetBytes<IMAGE_DOS_HEADER>(dllFile, 0x0);
	IMAGE_NT_HEADERS ntheaders = GetBytes<IMAGE_NT_HEADERS>(dllFile, dosheader2.e_lfanew);
	DWORD exportadr = RVAToOffset(dllFile, ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dosheader2, ntheaders);

	if (!ValidateOffset(exportadr, ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return nullptr;

	IMAGE_EXPORT_DIRECTORY exports = GetBytes<IMAGE_EXPORT_DIRECTORY>(dllFile, exportadr);

	DWORD offset = 0x0;
	DWORD adrOfNames = RVAToOffset(dllFile, exports.AddressOfNames, dosheader2, ntheaders);
	DWORD adrOfFunctions = RVAToOffset(dllFile, exports.AddressOfFunctions, dosheader2, ntheaders);
	DWORD adrOfOrdinals = RVAToOffset(dllFile, exports.AddressOfNameOrdinals, dosheader2, ntheaders);

	if (!ValidateOffset(exports.AddressOfNames, adrOfNames)
		|| !ValidateOffset(exports.AddressOfFunctions, adrOfFunctions)
		|| !ValidateOffset(exports.AddressOfNameOrdinals, adrOfOrdinals))
		return nullptr;

	DWORD tempByteOffset = exports.AddressOfNameOrdinals - adrOfOrdinals; // Could be any of the above

	for (DWORD i = 0; i < exports.NumberOfNames; i++)
	{
		offset = 0x0;
		std::vector<BYTE> tempByteVector;

		DWORD nameAdrs = GetBytes<DWORD>(dllFile, adrOfNames + i * 4);
		BYTE tempByte = 0x1;

		while (tempByte != 0x0)
		{
			tempByte = dllFile[nameAdrs + offset - tempByteOffset];
			offset++;

			tempByteVector.push_back(tempByte);
		}

		PCSTR func = (PSTR)tempByteVector.data();


		if (strcmp(func, function) != 0x0)
			continue;


		WORD ordTemp = GetBytes<WORD>(dllFile, adrOfOrdinals + i * 2);
		DWORD funcAdrs = GetBytes<DWORD>(dllFile, adrOfFunctions + ordTemp * 4);
		DWORD funcBytes = RVAToOffset(dllFile, funcAdrs, dosheader2, ntheaders);

		if (!ValidateOffset(funcAdrs, funcBytes))

			// Check for syscall instruction, return nullptr if not found... these offsets should not be hardcoded
			if (dllFile[funcBytes + 18] != 0x0f || dllFile[funcBytes + 19] != 0x05)
				return nullptr;

		WORD syscallId = GetBytes<WORD>(dllFile, funcBytes + 4);

		return GetSyscallFunction(syscallId);

	}

	return nullptr;
}

inline void* syscall_mem(PCSTR function)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll)
		return nullptr;

	PIMAGE_DOS_HEADER dosheader2 = (PIMAGE_DOS_HEADER)ntdll;
	PIMAGE_NT_HEADERS ntheaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dosheader2->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	DWORD* adrOfNames = (DWORD*)((BYTE*)ntdll + exports->AddressOfNames);
	DWORD* adrOfFunctions = (DWORD*)((BYTE*)ntdll + exports->AddressOfFunctions);
	WORD* adrOfOrdinals = (WORD*)((BYTE*)ntdll + exports->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exports->NumberOfNames; i++)
	{
		PCSTR func = (PSTR)((BYTE*)ntdll + adrOfNames[i]);

		if (strcmp(func, function) != 0x0)
			continue;

		BYTE* funcAdrs = (BYTE*)((BYTE*)ntdll + adrOfFunctions[adrOfOrdinals[i]]);

		WORD syscallId = GetSyscallIdMem(funcAdrs);

		if (syscallId == 0x0)
			return nullptr;

		return GetSyscallFunction(syscallId);
	}

	return nullptr;
}

#define SYSCALL(FunctionName) syscall(FunctionName)
#define SYSCALL_MEM(FunctionName) syscall_mem(FunctionName)