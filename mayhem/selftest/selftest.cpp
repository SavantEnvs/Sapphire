// Known-answer self-test for the Sapphire parsers the fuzz targets reach. Prints one
// "PASS <name>" / "FAIL <name>" line per check; mayhem/test.sh counts them.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <Crypt/base64.h>
#include <Network/CommonNetwork.h>
#include <Network/GamePacketParser.h>
#include <File.h>
#include <Exh.h>
#include <Exd.h>
#include <Logging/Logger.h>
#include <Navi/NaviProvider.h>
#include "fixtures.h"

using namespace Sapphire::Network::Packets;
static int g_fail = 0;
static void check( const char* name, bool ok )
{
  printf( "%s %s\n", ok ? "PASS" : "FAIL", name );
  if( !ok ) g_fail++;
}

static std::shared_ptr< xiv::dat::File > mkfile( const std::vector< uint8_t >& b )
{
  auto f = std::make_shared< xiv::dat::File >();
  f->access_data_sections().emplace_back( b.begin(), b.end() );
  return f;
}

int main()
{
  using Sapphire::Common::Util::base64Decode;
  using Sapphire::Common::Util::base64Encode;
  check( "base64_encode_hello", base64Encode( reinterpret_cast< const uint8_t* >( "hello" ), 5 ) == "aGVsbG8=" );
  check( "base64_decode_hello", base64Decode( "aGVsbG8=" ) == "hello" );
  check( "base64_decode_man", base64Decode( "TWFu" ) == "Man" );

  {
    auto buf = fx::frame( { "ABCD", "xyz" } );
    FFXIVARR_PACKET_HEADER h{};
    bool ok = getHeader( buf, 0, h ) == Success && h.count == 2 && h.size == buf.size();
    check( "packet_header", ok );
    std::vector< FFXIVARR_PACKET_RAW > l;
    ok = getPackets( buf, sizeof( h ), h, l ) == Success && l.size() == 2 &&
         std::string( l[ 0 ].data.begin(), l[ 0 ].data.end() ) == "ABCD" &&
         std::string( l[ 1 ].data.begin(), l[ 1 ].data.end() ) == "xyz" && l[ 0 ].segHdr.source_actor == 0x1111;
    check( "packet_segments", ok );
    std::vector< uint8_t > shortBuf( buf.begin(), buf.end() - 2 );
    l.clear();
    check( "packet_incomplete", getPackets( shortBuf, sizeof( h ), h, l ) == Incomplete );
    auto bad = fx::frame( { "ABCD" }, 4 );
    bad.resize( bad.size() + 4 );
    getHeader( bad, 0, h ); l.clear();
    check( "packet_size_mismatch_malformed", getPackets( bad, sizeof( h ), h, l ) == Malformed );
    std::vector< uint8_t > tiny( 10, 0 );
    check( "packet_header_incomplete", getHeader( tiny, 0, h ) == Incomplete );
  }

  try
  {
    auto exh = std::make_shared< xiv::exd::Exh >( *mkfile( fx::exh() ) );
    check( "exh_header", exh->get_header().field_count == 2 && exh->get_header().data_offset == 8 &&
                         exh->get_exd_defs().size() == 1 && exh->get_exd_defs()[ 0 ].count_id == 2 );
    xiv::exd::Exd exd( exh, { mkfile( fx::exd() ) } );
    auto& rows = exd.get_rows();
    bool ok = rows.size() == 2 &&
              std::get< uint32_t >( rows.at( 0 )[ 0 ] ) == 0x12345678u &&
              std::get< std::string >( rows.at( 0 )[ 1 ] ) == "hi" &&
              std::get< uint32_t >( rows.at( 1 )[ 0 ] ) == 42u &&
              std::get< std::string >( rows.at( 1 )[ 1 ] ) == "yo";
    check( "exd_rows", ok );
  }
  catch( const std::exception& e )
  {
    printf( "exception: %s\n", e.what() );
    check( "exh_header", false );
    check( "exd_rows", false );
  }

  {
    Sapphire::Logger::setLogLevel( 6 );
    char tmpl[] = "/tmp/sapphire_selftest_XXXXXX";
    std::string dir = mkdtemp( tmpl );
    auto good = fx::tset();
    std::ofstream( dir + "/a.nav", std::ios::binary ).write( reinterpret_cast< const char* >( good.data() ), good.size() );
    Sapphire::Common::Navi::NaviProvider p( "a" );
    check( "navmesh_load_tset", p.loadMesh( dir + "/a.nav" ) && p.hasNaviMesh() );
    check( "navmesh_cache_written", std::filesystem::exists( dir + "/a.navmesh_cache" ) &&
                                    std::filesystem::file_size( dir + "/a.navmesh_cache" ) > 0 );
    Sapphire::Common::Navi::NaviProvider p2( "a" );
    check( "navmesh_load_from_cache", p2.loadMesh( dir + "/a.nav" ) && p2.hasNaviMesh() );
    auto bad = fx::tset( 0x41414141 );
    std::ofstream( dir + "/b.nav", std::ios::binary ).write( reinterpret_cast< const char* >( bad.data() ), bad.size() );
    Sapphire::Common::Navi::NaviProvider p3( "b" );
    check( "navmesh_reject_bad_magic", !p3.loadMesh( dir + "/b.nav" ) );
    std::filesystem::remove_all( dir );
  }

  printf( "selftest: %d failed\n", g_fail );
  return g_fail ? 1 : 0;
}
