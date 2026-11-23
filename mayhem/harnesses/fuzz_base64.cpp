// Fuzzes Common::Util::base64Decode, which the api server applies to client-supplied JSON fields
// (src/api), then round-trips the result through base64Encode.
#include <cstdint>
#include <cstddef>
#include <string>
#include <Crypt/base64.h>

extern "C" int LLVMFuzzerTestOneInput( const uint8_t* data, size_t size )
{
  std::string in( reinterpret_cast< const char* >( data ), size );
  std::string dec = Sapphire::Common::Util::base64Decode( in );
  std::string enc = Sapphire::Common::Util::base64Encode(
    reinterpret_cast< const uint8_t* >( dec.data() ), static_cast< uint32_t >( dec.size() ) );
  (void)enc;
  return 0;
}
