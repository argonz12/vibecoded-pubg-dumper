// compile the zydis amalgamated source
// this file exists so the vcxproj only needs one .c entry
#define ZYDIS_STATIC_BUILD
#include "deps/zydis/amalgamated-dist/Zydis.c"
