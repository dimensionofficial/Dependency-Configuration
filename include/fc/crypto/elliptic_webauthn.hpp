#pragma once
#include <fc/crypto/bigint.hpp>
#include <fc/crypto/common.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/openssl.hpp>
#include <fc/fwd.hpp>
#include <fc/array.hpp>
#include <fc/io/raw_fwd.hpp>

namespace fc { namespace crypto { namespace webauthn {

namespace detail {
class public_key_impl;
}

typedef fc::array<char,33>           public_key_data;
typedef fc::array<char,320> signature_data;

class public_key {
   public:
      public_key();
      public_key(const public_key& k);
      ~public_key();
      public_key(const public_key_data& d);
      public_key( public_key&& pk );
      public_key& operator=( public_key&& pk );
      public_key& operator=( const public_key& pk );

      //bool verify(const fc::sha256& digest, const signature& sig);
      public_key_data serialize()const;

      operator public_key_data()const { return serialize(); }

      //check_canonical is a noop for webauthn key recovery
      public_key(const signature_data& c, const fc::sha256& digest, bool check_canonical = true);

      bool valid()const;

      inline friend bool operator==( const public_key& a, const public_key& b ) {
         return a.serialize() == b.serialize();
      }
      inline friend bool operator!=( const public_key& a, const public_key& b ) {
         return a.serialize() != b.serialize();
      }

   private:
      friend class private_key;
      //friend compact_signature signature_from_ecdsa(const EC_KEY* key, const public_key_data& pub_data, fc::ecdsa_sig& sig, const fc::sha256& d);
      fc::fwd<detail::public_key_impl, sizeof(public_key_data)> my;
};

struct public_key_shim : public crypto::shim<public_key_data> {
   using crypto::shim<public_key_data>::shim;

   bool valid()const {
      return public_key(_data).valid();
   }
};

struct signature_shim : public crypto::shim<signature_data> {
   using public_key_type = public_key_shim;
   using crypto::shim<signature_data>::shim;

   public_key_type recover(const sha256& digest, bool check_canonical) const {
      return public_key_type(public_key(_data, digest, check_canonical).serialize());
   }
};

#if 0
struct signature_thing {
   using data_type = signature_thing;

   public_key_shim recover(const sha256& digest, bool check_canonical) const {
      return public_key_shim();
   }

   const std::vector<uint8_t> serialize() const {
         return std::vector<uint8_t>(5);;
   }

       template<typename T>
    inline friend T& operator<<( T& ds, const signature_thing& ep ) {
      //ds.write( ep.data(), sizeof(ep) );
      return ds;
    }

    template<typename T>
    inline friend T& operator>>( T& ds, signature_thing& ep ) {
      //ds.read( ep.data(), sizeof(ep) );
      return ds;
    }
};
#endif

}}

#if 0
namespace raw {
template<typename Stream>
void unpack( Stream& s, crypto::webauthn::public_key& pk) {
   crypto::webauthn::public_key_data ser;
   fc::raw::unpack(s,ser);
   pk = fc::crypto::webauthn::public_key( ser );
}

template<typename Stream>
void pack( Stream& s, const crypto::webauthn::public_key& pk) {
   fc::raw::pack(s, pk.serialize());
}

template<typename Stream>
void unpack( Stream& s, crypto::webauthn::signature_thing& pk) {

}

template<typename Stream>
void pack( Stream& s, const crypto::webauthn::signature_thing& pk) {

}
}
#endif

}
#include <fc/reflect/reflect.hpp>

FC_REFLECT_TYPENAME( fc::crypto::webauthn::public_key )
FC_REFLECT_DERIVED( fc::crypto::webauthn::public_key_shim, (fc::crypto::shim<fc::crypto::webauthn::public_key_data>), BOOST_PP_SEQ_NIL )
FC_REFLECT_DERIVED( fc::crypto::webauthn::signature_shim, (fc::crypto::shim<fc::crypto::webauthn::signature_data>), BOOST_PP_SEQ_NIL )