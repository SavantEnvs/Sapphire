// Fuzzes the game-protocol framing that lobby/world GameConnection::onRecv runs on raw TCP bytes
// (src/common/Network/GamePacketParser.cpp). Mirrors onRecv: parse a frame header, dissect its
// segments, consume header.size bytes, repeat while frames parse.
#include <cstdint>
#include <cstddef>
#include <vector>
#include <Network/CommonNetwork.h>
#include <Network/GamePacketParser.h>

using namespace Sapphire::Network::Packets;

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  std::vector< uint8_t > buf( data, data + size );
  volatile uint32_t sink = 0;
  while( !buf.empty() )
  {
    FFXIVARR_PACKET_HEADER hdr{};
    if( getHeader( buf, 0, hdr ) != Success )
      break;
    std::vector< FFXIVARR_PACKET_RAW > list;
    if( getPackets( buf, sizeof( FFXIVARR_PACKET_HEADER ), hdr, list ) != Success )
      break;
    for( auto& p : list )
    {
      sink += p.segHdr.type;
      for( auto b : p.data )
        sink += b;
    }
    const auto consumed = static_cast< size_t >( hdr.size );
    buf.erase( buf.begin(), buf.begin() + consumed );
  }
  (void)sink;
  return 0;
}
