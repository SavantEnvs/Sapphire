// Fuzzes the datReader EXH (excel header) + EXD (excel data) parsers (deps/datReader/Exh.cpp,
// Exd.cpp) — the format of every game data table the world server loads via ExdData.
// Input: u32 LE length of the EXH part, then the EXH bytes, then the EXD bytes.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>
#include <File.h>
#include <Exh.h>
#include <Exd.h>

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  if( size < 4 )
    return -1;
  uint32_t exhLen;
  memcpy( &exhLen, data, 4 );
  data += 4; size -= 4;
  if( exhLen > size )
    return -1;

  auto exhFile = std::make_shared< xiv::dat::File >();
  exhFile->access_data_sections().emplace_back( reinterpret_cast< const char* >( data ),
                                                reinterpret_cast< const char* >( data ) + exhLen );
  auto exdFile = std::make_shared< xiv::dat::File >();
  exdFile->access_data_sections().emplace_back( reinterpret_cast< const char* >( data ) + exhLen,
                                                reinterpret_cast< const char* >( data ) + size );
  try
  {
    auto exh = std::make_shared< xiv::exd::Exh >( *exhFile );
    xiv::exd::Exd exd( exh, { exdFile } );
    try
    {
      const auto& rows = exd.get_rows();
      (void)rows.size();
    }
    catch( const std::exception& ) {}
    // Per-row access as ExdData does it: get_row(id) for plain sheets, get_row(id, subRow) for
    // sub-row sheets (header variant 2).
    const bool subRows = exh->get_header().variant == 2;
    for( auto& def : exh->get_exd_defs() )
    {
      for( uint32_t id = def.start_id; id < def.start_id + 4; ++id )
      {
        try
        {
          if( subRows )
          {
            exd.get_row( id, 0 );
            exd.get_row( id, 1 );
          }
          else
            exd.get_row( id );
        }
        catch( const std::exception& ) {}
      }
    }
  }
  catch( const std::exception& )
  {
  }
  return 0;
}
