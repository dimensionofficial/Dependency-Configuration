#include <fc/crypto/elliptic_webauthn.hpp>
#include <fc/crypto/elliptic_r1.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/crypto/openssl.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
#include <fc/io/json.hpp>

namespace fc { namespace crypto { namespace webauthn {

namespace detail {
class public_key_impl {
   public:
      public_key_data data;
};

struct client_data_json_object {
   std::string type;
   std::string challenge;
};
}
}}}
FC_REFLECT(fc::crypto::webauthn::detail::client_data_json_object, (type)(challenge))

namespace fc { namespace crypto { namespace webauthn {

bool public_key::valid() const {
   return true; ///XXX
}

public_key::public_key() {}
public_key::~public_key() {}
public_key::public_key(const public_key_data& dat) {
   my->data = dat;
}
public_key::public_key( const public_key& pk ) :my(pk.my) {}
public_key::public_key( public_key&& pk ) :my( fc::move( pk.my) ) {}
public_key& public_key::operator=( public_key&& pk ) {
   my = pk.my;
   return *this;
}
public_key& public_key::operator=( const public_key& pk ) {
   my = pk.my;
   return *this;
}

public_key_data public_key::serialize() const {
   return my->data;
}

public_key::public_key(const signature_data& c, const fc::sha256& digest, bool check_canonical) {
   fc::datastream<const char*> ds(c.data, c.size());

   fc::array<unsigned char, 65> compact_signature;
   std::vector<uint8_t> auth_data;
   std::string client_data;

   fc::raw::unpack(ds, compact_signature);
   fc::raw::unpack(ds, auth_data);
   fc::raw::unpack(ds, client_data);

   //XXXX read client_data and check challenge == digest
   variant client_data_obj = fc::json::from_string(client_data).get_object();
   FC_ASSERT(client_data_obj["type"].as_string() == "webauthn.get", "Wrong webauth signature type");
   std::string challenge_bytes = fc::base64url_decode(client_data_obj["challenge"].as_string());
   FC_ASSERT(fc::sha256(challenge_bytes.data(), challenge_bytes.size()) == digest, "Wrong webauthn challenge");

   //the signature (and thus public key we need to return) will be over
   // sha256(auth_data || client_data_hash)
   fc::sha256 client_data_hash = fc::sha256::hash(client_data);
   fc::sha256::encoder e;
   e.write((char*)auth_data.data(), auth_data.size());
   e.write(client_data_hash.data(), client_data_hash.data_size());
   fc::sha256 signed_digest = e.result();

   //quite a bit of this copied ffrom elliptic_r1, can probably commonize
   int nV = compact_signature.data[0];
   if (nV<31 || nV>=35)
      FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );
   ecdsa_sig sig = ECDSA_SIG_new();
   BIGNUM *r = BN_new(), *s = BN_new();
   BN_bin2bn(&compact_signature.data[1],32,r);
   BN_bin2bn(&compact_signature.data[33],32,s);
   ECDSA_SIG_set0(sig, r, s);

   fc::ec_key key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
   nV -= 4;

   if (r1::ECDSA_SIG_recover_key_GFp(key, sig, (uint8_t*)signed_digest.data(), signed_digest.data_size(), nV - 27, 0) == 1) {
      const EC_POINT* point = EC_KEY_get0_public_key(key);
      const EC_GROUP* group = EC_KEY_get0_group(key);
      size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, (uint8_t*)my->data.data, my->data.size(), NULL);
      if(sz == my->data.size())
         return;
   }
   FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );
}

}}}