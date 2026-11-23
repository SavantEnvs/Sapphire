// Fuzzes Common::Navi::NaviProvider::loadMesh (src/common/Navi/NaviProvider.cpp), the loader the
// world server runs on every zone's .nav tile-cache set (TSET header, FastLZ tiles, dtTileCache /
// dtNavMesh build), including the .navmesh_cache sidecar reader/writer (NavMeshCacheIO.cpp), then
// runs a path query over whatever mesh loaded.
// Input: u32 LE length of the .nav part, then the .nav bytes, then the .navmesh_cache bytes (written
// after the .nav so it counts as fresh; empty = no cache file, loadMesh then writes one itself).
// Each input gets its own fresh directory under $TMPDIR, removed afterwards.
#include <memory>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <Logging/Logger.h>
#include <Navi/NaviProvider.h>

static std::string g_base;

static void writeFile( const std::string& p, const uint8_t* d, size_t n )
{
  FILE* f = fopen( p.c_str(), "wb" );
  if( !f )
    abort();
  if( n )
    fwrite( d, 1, n, f );
  fclose( f );
}

extern "C" int LLVMFuzzerInitialize( int*, char*** )
{
  // Logging is process-global and fixed for the whole run (read-only across inputs).
  Sapphire::Logger::setLogLevel( 6 /* spdlog::level::off */ );
  const char* tmp = getenv( "TMPDIR" );
  std::string tmpl = std::string( tmp && *tmp ? tmp : "/tmp" ) + "/navmesh_fuzz_XXXXXX";
  if( !mkdtemp( tmpl.data() ) )
    abort();
  g_base = tmpl;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  if( size < 4 )
    return -1;
  uint32_t navLen;
  memcpy( &navLen, data, 4 );
  data += 4; size -= 4;
  if( navLen > size )
    return -1;

  const std::string dir = g_base + "/z";
  std::filesystem::remove_all( dir );
  std::filesystem::create_directory( dir );
  const std::string nav = dir + "/zone.nav";
  writeFile( nav, data, navLen );
  if( size > navLen )
    writeFile( dir + "/zone.navmesh_cache", data + navLen, size - navLen );

  {
    Sapphire::Common::Navi::NaviProvider provider( "zone" );
    if( provider.loadMesh( nav ) && provider.hasNaviMesh() )
    {
      provider.initQuery();
      auto path = provider.findFollowPath( { 0.f, 0.f, 0.f }, { 10.f, 0.f, 10.f } );
      (void)path;
      auto pos = provider.findNearestPosition( 1.f, 1.f );
      (void)pos;
    }
  }
  std::filesystem::remove_all( dir );
  return 0;
}
