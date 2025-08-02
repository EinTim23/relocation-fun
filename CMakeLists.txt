cmake_minimum_required (VERSION 3.12)
project("reloc_fun" C CXX)

#setup global compiler flags. We need to disable stack cookies
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS-")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS-")

add_executable (builder src/builder.cpp)
add_executable(shellcode src/shellcode.cpp)
set_property(TARGET builder PROPERTY CXX_STANDARD 17)
set_property(TARGET shellcode PROPERTY CXX_STANDARD 17)

target_link_options(shellcode PUBLIC "/EMITPOGOPHASEINFO" "/NODEFAULTLIB" "/DYNAMICBASE:NO" "/FIXED" "/ENTRY:\"shellcode\"")

target_link_libraries(builder PUBLIC kernel32.lib msvcrt.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib DbgHelp.lib)
add_dependencies(builder shellcode)