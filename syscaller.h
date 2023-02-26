#pragma once
#include <memoryapi.h>
#include <libloaderapi.h>

//
// Helper functions
//

template <typename RetVal>
static inline auto GetBytes(unsigned char* bytes, uint32_t offset, size_t custom_size = 0) -> RetVal
{
	if (custom_size == 0)
		custom_size = sizeof(RetVal);

	std::vector<unsigned char>buffer(bytes + offset, bytes + offset + custom_size);

	return *reinterpret_cast<RetVal*>(buffer.data());
}

static uint32_t RVAToOffset(unsigned char* bytes, uint32_t offset, IMAGE_DOS_HEADER dosheader, IMAGE_NT_HEADERS ntheader)
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

static inline uint16_t IdFromBytes(unsigned char* bytes, uint32_t offset)
{
	for (uint32_t i = 0; i < (0x20 - 0x5); i++)
		if (*reinterpret_cast<uint8_t*>(bytes + offset + i) == 0xb8)
			return GetBytes<uint16_t>(bytes, offset + i + 1);

	return 0x0;
}

inline static uint16_t IdFromBytesMem(uint8_t* bytes)
{
	uint32_t offset = 0x0;
	
	while (true)
	{
		if (offset >= 0x17) // 0x20 - 0x08 - 0x01
			break;

		if (bytes[offset] == 0xb8)
			return *reinterpret_cast<uint16_t*>(bytes + offset + 1);


		offset++;
	}

	return 0x0;
}

static inline void* GetSyscallFunction_x64(uint16_t SyscallId)
{
	uint8_t id[2];
	memcpy(id, &SyscallId, sizeof(uint16_t));


	const uint8_t sc[] = {
		// mov rax, gs: [0x60]
		// mov r10, rcx
		// mov eax, SyscallId
		// syscall
		// retn
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
		0x00, 0x00,
		0x4C, 0x8B, 0xD1,
		0xB8, id[0], id[1], 0x00, 0x00,
		0x0f, 0x05,
		0xC3
	};

	void* exec = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(exec, sc, sizeof sc);

	return exec;
}

static inline void* GetSyscallFunction_x86(uint16_t SyscallId)
{
	uint8_t id[2];
	memcpy(id, &SyscallId, sizeof(uint16_t));

	// This shellcode is a modified version of the following implementation of Heavens Gate:
	// https://github.com/JustasMasiulis/wow64pp/blob/4573048c41657cf66555a87a736720ab8712cbdd/include/wow64pp.hpp#L692

	const uint8_t sc[] = {
		// push ebp
		// mov ebp, esp
		// and esp, 0xFFFFFFF0
		0x55,
		0x89, 0xE5,
		0x83, 0xE4, 0xF0,

		// push 0x33
		// push _next_64bit_block
		// retf
		0x6A, 0x33, 
		0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05,
		0xCB,

		// First param is "this" (offset 0)
		// Second param is amount of args beyond 4 (offset 8)
		0x67, 0x48, 0x8B, 0x45, 8,	// mov rax, [ebp + 8]  Args beyond 4
		0x67, 0x48, 0x8B, 0x4D, 16, // mov rcx, [ebp + 16]
		0x67, 0x48, 0x8B, 0x55, 24, // mov rdx, [ebp + 24]
		0x67, 0x4C, 0x8B, 0x45, 32, // mov r8,  [ebp + 32]
		0x67, 0x4C, 0x8B, 0x4D, 40, // mov r9,  [ebp + 40]


		// test rax, rax
		// je 0x0C		 ;Jump to syscall
		// push [rdi]
		// sub rdi, 8
		// sub rax, 1
		// jmp _ls		 ;Jump to beginning of loop
		0x48, 0x85, 0xC0,
		0x74, 0x0C,
		0xFF, 0x37,
		0x48, 0x83, 0xEF, 0x08,
		0x48, 0x83, 0xE8, 0x01, 
		0xEB, 0xEF,


		// mov rax, gs: [0x60]
		// mov r10, rcx
		// mov eax, SyscallId
		// syscall
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
		0x00, 0x00,
		0x4C, 0x8B, 0xD1,
		0xB8, id[0], id[1], 0x00, 0x00,
		0x0f, 0x05,

		// mov [edi], eax	;Store return value from syscall
		0x89, 0xC7,
		
		// push 0x23
		// push _next_32bit_block
		// retfq
		0xE8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x0D, 
		0xCB,

		// mov ax, ds
		// mov ss, eax
		0x66, 0x8C, 0xD8,
		0x8E, 0xD0,

		// mov eax, [edi]     ;Move return value from syscall into eax.
		// mov esp, ebp
		// pop ebp
		// ret
		0x89, 0xF8,
		0x89, 0xEC,
		0x5D,
		0xC3
	};

	void* exec = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(exec, sc, sizeof sc);

	return exec;
}

static inline bool ValidateOffset(uint32_t RVA, uint32_t offset)
{
	return !(RVA == offset);
}

static inline uint16_t GetSyscallIdMem(const char* function)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll)
		return NULL;


	PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)ntdll;
	PIMAGE_NT_HEADERS ntheaders = (PIMAGE_NT_HEADERS)((uint8_t*)ntdll + dosheader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)ntdll + ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	uint32_t* adrOfNames = (uint32_t*)((uint8_t*)ntdll + exports->AddressOfNames);
	uint32_t* adrOfFunctions = (uint32_t*)((uint8_t*)ntdll + exports->AddressOfFunctions);
	uint16_t* adrOfOrdinals = (uint16_t*)((uint8_t*)ntdll + exports->AddressOfNameOrdinals);

	for (uint32_t i = 0; i < exports->NumberOfNames; i++)
	{
		const char* func = (char*)((uint8_t*)ntdll + adrOfNames[i]);

		if (strcmp(func, function) != 0x0)
			continue;

		uint8_t* funcAdrs = (uint8_t*)((uint8_t*)ntdll + adrOfFunctions[adrOfOrdinals[i]]);

		uint16_t syscallId = IdFromBytesMem(funcAdrs);

		if (syscallId == 0x0)
			return NULL;

		return syscallId;
	}

	return NULL;
}


// From disk
static inline uint16_t GetSyscallId(const char* function)
{
	std::ifstream input("C:\\Windows\\System32\\ntdll.dll", std::ios::binary);

	if (!input) // Can't open ntdll.dll for some reason
		return NULL;

	std::vector<uint8_t> temp(
		(std::istreambuf_iterator<char>(input)),
		(std::istreambuf_iterator<char>()));

	input.close();
	uint8_t* dllFile = temp.data();

	IMAGE_DOS_HEADER dosheader = GetBytes<IMAGE_DOS_HEADER>(dllFile, 0x0);
	IMAGE_NT_HEADERS ntheaders = GetBytes<IMAGE_NT_HEADERS>(dllFile, dosheader.e_lfanew);
	uint32_t exportadr = RVAToOffset(dllFile, ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dosheader, ntheaders);

	if (!ValidateOffset(exportadr, ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return NULL;

	IMAGE_EXPORT_DIRECTORY exports = GetBytes<IMAGE_EXPORT_DIRECTORY>(dllFile, exportadr);

	uint32_t offset = 0x0;
	uint32_t adrOfNames = RVAToOffset(dllFile, exports.AddressOfNames, dosheader, ntheaders);
	uint32_t adrOfFunctions = RVAToOffset(dllFile, exports.AddressOfFunctions, dosheader, ntheaders);
	uint32_t adrOfOrdinals = RVAToOffset(dllFile, exports.AddressOfNameOrdinals, dosheader, ntheaders);

	if (!ValidateOffset(exports.AddressOfNames, adrOfNames)
		|| !ValidateOffset(exports.AddressOfFunctions, adrOfFunctions)
		|| !ValidateOffset(exports.AddressOfNameOrdinals, adrOfOrdinals))
		return NULL;

	uint32_t tempByteOffset = exports.AddressOfNameOrdinals - adrOfOrdinals; // Could be any of the above

	for (uint32_t i = 0; i < exports.NumberOfNames; i++)
	{
		offset = 0x0;
		std::vector<uint8_t> tempByteVector;

		uint32_t nameAdrs = GetBytes<uint32_t>(dllFile, adrOfNames + i * 4);
		uint8_t tempByte = 0x1; // Random

		while (tempByte != 0x0)
		{
			tempByte = dllFile[nameAdrs + offset - tempByteOffset];
			offset++;

			tempByteVector.push_back(tempByte);
		}

		const char* func = (char*)tempByteVector.data();


		if (strcmp(func, function) != 0x0)
			continue;


		uint16_t ordTemp = GetBytes<uint16_t>(dllFile, adrOfOrdinals + i * 2);
		uint32_t funcAdrs = GetBytes<uint32_t>(dllFile, adrOfFunctions + ordTemp * 4);
		uint32_t funcBytes = RVAToOffset(dllFile, funcAdrs, dosheader, ntheaders);

		if (!ValidateOffset(funcAdrs, funcBytes))
			return NULL;

		return IdFromBytes(dllFile, funcBytes);
	}

	return NULL;
}


//
// Main functions
//

inline void* syscall_x64(const char* function, bool mem = false)
{
	auto syscallId = mem ? GetSyscallIdMem(function) : GetSyscallId(function);

	if (syscallId == NULL)
		return nullptr;

	return GetSyscallFunction_x64(syscallId);

}

template <typename RetVal, typename... Args>
inline auto syscall_x86(const char* function, bool mem = false)
{
	const auto syscallId = mem ? GetSyscallIdMem(function) : GetSyscallId(function);
	const auto sc = (RetVal(*)(uint64_t ...))GetSyscallFunction_x86(syscallId);

	return [sc](Args ... args) -> RetVal
	{
		return reinterpret_cast<RetVal(*)(uint64_t ...)>(sc)(
			sizeof...(Args) > 4 ? (sizeof...(Args) - 4) : 0,
			(uint64_t)(args)...
		);
	};
}


//
// Macros
//

#define SYSCALL_X64(FunctionName) syscall_x64(FunctionName)
#define SYSCALL_MEM_X64(FunctionName) syscall_x64(FunctionName, true)

#define SYSCALL_X86(FunctionName, RetVal, ...) syscall_x86<RetVal, ##__VA_ARGS__>(FunctionName)
#define SYSCALL_MEM_X86(FunctionName, RetVal, ...) syscall_x86<RetVal, ##__VA_ARGS__>(FunctionName, true)


#if defined(_WIN64)

#define SYSCALL SYSCALL_X64
#define SYSCALL_MEM SYSCALL_MEM_X64

#elif defined(_WIN32)

#define SYSCALL SYSCALL_X86
#define SYSCALL_MEM SYSCALL_MEM_X86

#endif
