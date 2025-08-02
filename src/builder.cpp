#include <Windows.h>
#include <fstream>
#include <vector>

#define file_alignment_size 512
#define memory_alignment_size 4096
#define fucked_up_base 0x2234567812340000
#define windows_fallback_base 0x10000

DWORD64 _align(DWORD64 size, DWORD64 align, DWORD64 addr = 0) {
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

int main(int argc, char* argv[]) {
    uint64_t delta = windows_fallback_base - fucked_up_base;
    std::vector<uint8_t> shellcode_buffer;

    std::ifstream stub_pe_file_reader("shellcode.exe", std::ios::binary);
    std::vector<uint8_t> stub_pe_file_buffer(std::istreambuf_iterator<char>(stub_pe_file_reader), {});
    char* buffer = (char*)stub_pe_file_buffer.data();

    PIMAGE_DOS_HEADER stub_pe_dos_header = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 stub_pe_nt_header = (PIMAGE_NT_HEADERS64)(buffer + stub_pe_dos_header->e_lfanew);
    IMAGE_SECTION_HEADER* stub_section_header =
        (IMAGE_SECTION_HEADER*)(((ULONG_PTR)&stub_pe_nt_header->OptionalHeader) +
                                stub_pe_nt_header->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < stub_pe_nt_header->FileHeader.NumberOfSections; i++) {
        if (strcmp(".text", (char*)stub_section_header[i].Name) == 0) {
            auto textSection = stub_section_header[i];
            for (int j = 0; j < textSection.SizeOfRawData; j++)
                shellcode_buffer.push_back(stub_pe_file_buffer.at(textSection.PointerToRawData + j));
        }
    }

    printf("Extracted shellcode: %d bytes\n", shellcode_buffer.size());
    for (int i = 0; i < shellcode_buffer.size(); i += 8) {
        uint64_t* data = (uint64_t*)(shellcode_buffer.data() + i);
        *data -= delta;
    }

    IMAGE_DOS_HEADER dos_h{};
    dos_h.e_magic = IMAGE_DOS_SIGNATURE;
    dos_h.e_cblp = 0x0090;
    dos_h.e_cp = 0x0003;
    dos_h.e_crlc = 0x0000;
    dos_h.e_cparhdr = 0x0004;
    dos_h.e_minalloc = 0x0000;
    dos_h.e_maxalloc = 0xFFFF;
    dos_h.e_ss = 0x0000;
    dos_h.e_sp = 0x00B8;
    dos_h.e_csum = 0x0000;
    dos_h.e_ip = 0x0000;
    dos_h.e_cs = 0x0000;
    dos_h.e_lfarlc = 0x0040;
    dos_h.e_ovno = 0x0000;
    dos_h.e_oemid = 0x0000;
    dos_h.e_oeminfo = 0x0000;
    dos_h.e_lfanew = 0x0040;

    IMAGE_NT_HEADERS64 nt_h64{};
    nt_h64.Signature = IMAGE_NT_SIGNATURE;
    nt_h64.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt_h64.FileHeader.NumberOfSections = 1;
    nt_h64.FileHeader.TimeDateStamp = 0x00000000;
    nt_h64.FileHeader.PointerToSymbolTable = 0x0;
    nt_h64.FileHeader.NumberOfSymbols = 0x0;
    nt_h64.FileHeader.SizeOfOptionalHeader = 0x00F0;

    nt_h64.FileHeader.Characteristics = IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_EXECUTABLE_IMAGE;

    nt_h64.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt_h64.OptionalHeader.MajorLinkerVersion = 1;
    nt_h64.OptionalHeader.MinorLinkerVersion = 0;
    nt_h64.OptionalHeader.SizeOfCode = 0x00000200;
    nt_h64.OptionalHeader.SizeOfInitializedData = 0x00000200;
    nt_h64.OptionalHeader.SizeOfUninitializedData = 0x0;
    nt_h64.OptionalHeader.AddressOfEntryPoint = stub_pe_nt_header->OptionalHeader.AddressOfEntryPoint;
    nt_h64.OptionalHeader.BaseOfCode = 0x00001000;
    nt_h64.OptionalHeader.ImageBase = fucked_up_base;
    nt_h64.OptionalHeader.SectionAlignment = memory_alignment_size;
    nt_h64.OptionalHeader.FileAlignment = file_alignment_size;
    nt_h64.OptionalHeader.MajorOperatingSystemVersion = 0x0;
    nt_h64.OptionalHeader.MinorOperatingSystemVersion = 0x0;
    nt_h64.OptionalHeader.MajorImageVersion = 0x0006;
    nt_h64.OptionalHeader.MinorImageVersion = 0x0000;
    nt_h64.OptionalHeader.MajorSubsystemVersion = 0x0006;
    nt_h64.OptionalHeader.MinorSubsystemVersion = 0x0000;
    nt_h64.OptionalHeader.Win32VersionValue = 0x0;
    nt_h64.OptionalHeader.SizeOfImage = 0x00003000;
    nt_h64.OptionalHeader.SizeOfHeaders = _align(0x00000200, file_alignment_size);
    nt_h64.OptionalHeader.CheckSum = 0x0000F3A6;
    nt_h64.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt_h64.OptionalHeader.DllCharacteristics = 0x8120;
    nt_h64.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;
    nt_h64.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;
    nt_h64.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;
    nt_h64.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;
    nt_h64.OptionalHeader.LoaderFlags = 0x00000000;
    nt_h64.OptionalHeader.NumberOfRvaAndSizes = 0x00000010;

    IMAGE_BASE_RELOCATION reloc{};
    reloc.VirtualAddress = 0x1000;
    reloc.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * (shellcode_buffer.size() / 8);
    std::vector<WORD> reloc_entries{};
    for (int i = 0; i < shellcode_buffer.size(); i += 8) {
        reloc_entries.push_back((IMAGE_REL_BASED_DIR64 << 12) | (i & 0xFFF));
    }

    IMAGE_SECTION_HEADER c_sec{};

    strcpy((char*)c_sec.Name, "yes");
    c_sec.Misc.VirtualSize =
        _align(shellcode_buffer.size() + sizeof(IMAGE_BASE_RELOCATION) + reloc_entries.size() * sizeof(WORD),
               memory_alignment_size);
    c_sec.VirtualAddress = memory_alignment_size;
    c_sec.SizeOfRawData = _align(
        shellcode_buffer.size() + sizeof(IMAGE_BASE_RELOCATION) + reloc_entries.size() * sizeof(WORD), file_alignment_size);
    c_sec.PointerToRawData = _align(0x00000200, file_alignment_size);
    c_sec.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    nt_h64.OptionalHeader.SizeOfImage = _align(c_sec.VirtualAddress + c_sec.Misc.VirtualSize, memory_alignment_size);
    nt_h64.FileHeader.Characteristics = 0x0022;
    nt_h64.FileHeader.TimeDateStamp = 0x420;
    nt_h64.OptionalHeader.CheckSum = 0x1337;
    nt_h64.OptionalHeader.SizeOfCode = c_sec.SizeOfRawData;
    nt_h64.OptionalHeader.SizeOfInitializedData = c_sec.SizeOfRawData + c_sec.SizeOfRawData;
    nt_h64.OptionalHeader.Subsystem = 0x0003;

    nt_h64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress =
        c_sec.VirtualAddress + shellcode_buffer.size();
    nt_h64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size =
        sizeof(reloc) + sizeof(WORD) * (shellcode_buffer.size() / 8);

    printf("Writing to disk...\n");
    std::fstream pe_writer;
    pe_writer.open("out.exe", std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    pe_writer.write((char*)&dos_h, sizeof dos_h);
    pe_writer.write((char*)&nt_h64, sizeof nt_h64);

    pe_writer.write((char*)&c_sec, sizeof c_sec);
    while (pe_writer.tellp() != c_sec.PointerToRawData) pe_writer.put(0x0);

    printf("Writing shellcode...\n");
    size_t current_pos = pe_writer.tellp();
    pe_writer.write((const char*)shellcode_buffer.data(), shellcode_buffer.size());
    pe_writer.write((char*)&reloc, sizeof(reloc));
    pe_writer.write((char*)reloc_entries.data(), reloc_entries.size() * sizeof(WORD));

    while (pe_writer.tellp() != current_pos + c_sec.SizeOfRawData) pe_writer.put(0x0);

    pe_writer.close();
    printf("Done!\n");
    return 0;
}