// Fuzzes the datReader SqPack container readers (deps/datReader/SqPack.cpp, Index.cpp, Dat.cpp,
// DatZlib.cpp) the way GameData opens game files: the input is written to a file, opened as an
// .index (hash table walk) and as a .dat, and every file the index points at is extracted from it
// (standard/model/texture block tables + zlib inflate).
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <Index.h>
#include <Dat.h>
#include <File.h>

static std::string g_path;

extern "C" int LLVMFuzzerInitialize( int*, char*** )
{
  const char* tmp = getenv( "TMPDIR" );
  std::string tmpl = std::string( tmp && *tmp ? tmp : "/tmp" ) + "/sqpack_fuzz_XXXXXX";
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

  std::vector< uint32_t > offsets;
  try
  {
    xiv::dat::Index idx( g_path );
    for( auto& dir : idx.getHashTable() )
      for( auto& file : dir.second )
        if( offsets.size() < 16 )
          offsets.push_back( file.second.datOffset );
  }
  catch( const std::exception& ) {}
  catch( const std::exception* e ) { delete e; }

  // An index with no entries still gets one extraction attempt right after the SqPack headers.
  if( offsets.empty() )
    offsets.push_back( 0x800 );

  try
  {
    xiv::dat::Dat dat( g_path, 0 );
    for( auto off : offsets )
    {
      try { auto file = dat.getFile( off ); (void)file; } catch( const std::exception& ) {}
    }
  }
  catch( const std::exception& ) {}
  catch( const std::exception* e ) { delete e; }
  return 0;
}
