// Byte fixtures shared by the self-test and the seed generator.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace fx
{
  inline void be16( std::vector< uint8_t >& v, uint16_t x ) { v.push_back( x >> 8 ); v.push_back( x & 0xff ); }
  inline void be32( std::vector< uint8_t >& v, uint32_t x ) { for( int s = 24; s >= 0; s -= 8 ) v.push_back( ( x >> s ) & 0xff ); }
  inline void le32( std::vector< uint8_t >& v, uint32_t x ) { for( int s = 0; s < 32; s += 8 ) v.push_back( ( x >> s ) & 0xff ); }
  inline void le16( std::vector< uint8_t >& v, uint16_t x ) { v.push_back( x & 0xff ); v.push_back( x >> 8 ); }
  inline void le64( std::vector< uint8_t >& v, uint64_t x ) { for( int s = 0; s < 64; s += 8 ) v.push_back( ( x >> s ) & 0xff ); }
  inline void pad( std::vector< uint8_t >& v, size_t n ) { while( v.size() < n ) v.push_back( 0 ); }
  inline void f32( std::vector< uint8_t >& v, float f ) { uint32_t x; memcpy( &x, &f, 4 ); le32( v, x ); }

  // One FFXIV frame (40-byte header) holding one segment per payload.
  inline std::vector< uint8_t > frame( const std::vector< std::string >& payloads, uint32_t sizeDelta = 0 )
  {
    std::vector< uint8_t > body;
    for( auto& p : payloads )
    {
      le32( body, 16 + p.size() ); le32( body, 0x1111 ); le32( body, 0x2222 ); le16( body, 3 ); le16( body, 0 );
      body.insert( body.end(), p.begin(), p.end() );
    }
    std::vector< uint8_t > v;
    le64( v, 0 ); le64( v, 0 ); le64( v, 1700000000000ull );
    le32( v, 40 + body.size() + sizeDelta ); le16( v, 1 ); le16( v, payloads.size() );
    v.push_back( 0 ); v.push_back( 0 ); le16( v, 0 ); le32( v, 0 );
    v.insert( v.end(), body.begin(), body.end() );
    return v;
  }

  // EXH: two members (uint32 @0, string @4), one page [0,2), one language.
  inline std::vector< uint8_t > exh()
  {
    std::vector< uint8_t > v{ 'E', 'X', 'H', 'F' };
    be16( v, 3 ); be16( v, 8 ); be16( v, 2 ); be16( v, 1 ); be16( v, 1 ); be16( v, 0 );
    v.push_back( 0 ); v.push_back( 1 );
    pad( v, 0x20 );
    be16( v, 7 ); be16( v, 0 );
    be16( v, 0 ); be16( v, 4 );
    be32( v, 0 ); be32( v, 2 );
    le16( v, 1 );
    return v;
  }

  // EXD: rows 0 -> (0x12345678, "hi"), 1 -> (42, "yo").
  inline std::vector< uint8_t > exd()
  {
    std::vector< uint8_t > v{ 'E', 'X', 'D', 'F' };
    be16( v, 2 ); be16( v, 0 ); be32( v, 16 );
    pad( v, 0x20 );
    be32( v, 0 ); be32( v, 0x30 );
    be32( v, 1 ); be32( v, 0x48 );
    pad( v, 0x30 );
    be32( v, 11 ); be16( v, 1 ); be32( v, 0x12345678 ); be32( v, 0 ); v.push_back( 'h' ); v.push_back( 'i' ); v.push_back( 0 );
    pad( v, 0x48 );
    be32( v, 11 ); be16( v, 1 ); be32( v, 42 ); be32( v, 0 ); v.push_back( 'y' ); v.push_back( 'o' ); v.push_back( 0 );
    return v;
  }

  // TSET tile-cache set header with no tiles (TileCacheSetHeader layout, little-endian).
  inline std::vector< uint8_t > tset( int magic = 'T' << 24 | 'S' << 16 | 'E' << 8 | 'T' )
  {
    std::vector< uint8_t > v;
    le32( v, magic ); le32( v, 1 ); le32( v, 0 );
    // dtNavMeshParams
    f32( v, 0 ); f32( v, 0 ); f32( v, 0 ); f32( v, 48 ); f32( v, 48 ); le32( v, 64 ); le32( v, 4096 );
    // dtTileCacheParams
    f32( v, 0 ); f32( v, 0 ); f32( v, 0 ); f32( v, 0.25f ); f32( v, 0.2f ); le32( v, 192 ); le32( v, 192 );
    f32( v, 2 ); f32( v, 0.6f ); f32( v, 0.9f ); f32( v, 1.3f ); le32( v, 256 ); le32( v, 128 );
    return v;
  }
}
