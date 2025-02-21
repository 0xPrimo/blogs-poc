cmake_minimum_required (VERSION 3.8)

if(NOT WIN32)
    # Compiler
    set( CMAKE_C_COMPILER "/usr/bin/x86_64-w64-mingw32-gcc" )
    
    # CFlags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-int-conversion")

    #link_libraries(winhttp)
    #link_libraries(iphlpapi)
endif()

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("Simple-Loader" C)


set( SOURCES 
 "Source/Main.c"
)

add_executable( ${PROJECT_NAME}
    ${SOURCES}
)
