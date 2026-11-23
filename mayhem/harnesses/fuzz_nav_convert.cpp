// Runs the nav_convert tool (src/tools/nav_convert/main.cpp, compiled with -Dmain=nav_convert_main)
// on each input as its <input_navmesh.bin>: the tool's own MSET reader, dtNavMesh::addTile on the
// raw tile blobs, and the OBJ export walk over polys and off-mesh links (output to /dev/null).
// The tool reports bad input by return code and exceptions it catches itself; it never exit()s.
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

int nav_convert_main( int argc, char** argv );

static std::string g_path;

extern "C" int LLVMFuzzerInitialize( int*, char*** )
{
  const char* tmp = getenv( "TMPDIR" );
  std::string tmpl = std::string( tmp && *tmp ? tmp : "/tmp" ) + "/nav_convert_fuzz_XXXXXX";
  int fd = mkstemp( tmpl.data() );
  if( fd < 0 )
    abort();
  close( fd );
  g_path = tmpl;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  FILE* f = fopen( g_path.c_str(), "wb" );
  if( !f )
    abort();
  fwrite( data, 1, size, f );
  fclose( f );
  std::string a0 = "nav_convert", a1 = g_path, a2 = "/dev/null", a3 = "--with-offmesh";
  char* argv[] = { a0.data(), a1.data(), a2.data(), a3.data(), nullptr };
  nav_convert_main( 4, argv );
  return 0;
}
