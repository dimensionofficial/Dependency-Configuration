#include <fc/fwd_impl.hpp>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "_elliptic_impl_priv.hpp"

/* used by mixed + secp256k1 */

namespace fc { namespace ecc {
    namespace detail {

        private_key_impl::private_key_impl() BOOST_NOEXCEPT
        {
            _init_lib();
        }

        private_key_impl::private_key_impl( const private_key_impl& cpy ) BOOST_NOEXCEPT
        {
            _init_lib();
            this->_key = cpy._key;
        }

        private_key_impl& private_key_impl::operator=( const private_key_impl& pk ) BOOST_NOEXCEPT
        {
            _key = pk._key;
            return *this;
        }
    }

    static const private_key_secret empty_priv;

    private_key::private_key() {}

    private_key::private_key( const private_key& pk ) : my( pk.my ) {}

    private_key::private_key( private_key&& pk ) : my( std::move( pk.my ) ) {}

    private_key::~private_key() {}

    private_key& private_key::operator=( private_key&& pk )
    {
        my = std::move( pk.my );
        return *this;
    }

    private_key& private_key::operator=( const private_key& pk )
    {
        my = pk.my;
        return *this;
    }

    private_key private_key::regenerate( const fc::sha256& secret )
    {
       private_key self;
       self.my->_key = secret;
       return self;
    }

    fc::sha256 private_key::get_secret()const
    {
        return my->_key;
    }

    private_key::private_key( EC_KEY* k )
    {
       my->_key = get_secret( k );
       EC_KEY_free(k);
    }

    public_key private_key::get_public_key()const
    {
       FC_ASSERT( my->_key != empty_priv );
       public_key_data pub;
       size_t pub_len = sizeof(pub);
       secp256k1_pubkey secp_pub;
       FC_ASSERT( secp256k1_ec_pubkey_create( detail::_get_context(), &secp_pub, (unsigned char*) my->_key.data() ) );
       secp256k1_ec_pubkey_serialize( detail::_get_context(), (unsigned char*)&pub, &pub_len, &secp_pub, SECP256K1_EC_COMPRESSED );
       FC_ASSERT( pub_len == pub.size() );
       return public_key(pub);
    }

    static int extended_nonce_function( unsigned char *nonce32, const unsigned char *msg32,
                                        const unsigned char *key32, const unsigned char* algo16,
                                        void* data, unsigned int attempt ) {
        unsigned int* extra = (unsigned int*) data;
        (*extra)++;
        return secp256k1_nonce_function_default( nonce32, msg32, key32, algo16, nullptr, *extra );
    }

#if 0
/** Create a recoverable ECDSA signature.
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_sign_recoverable(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
#endif

    compact_signature private_key::sign_compact( const fc::sha256& digest, bool require_canonical )const
    {
        FC_ASSERT( my->_key != empty_priv );
        compact_signature result;
        secp256k1_ecdsa_recoverable_signature secp_sig;
        int recid;
        unsigned int counter = 0;
        do
        {
            FC_ASSERT( secp256k1_ecdsa_sign_recoverable( detail::_get_context(), &secp_sig, (unsigned char*) digest.data(), (unsigned char*) my->_key.data(), extended_nonce_function, &counter ));
            secp256k1_ecdsa_recoverable_signature_serialize_compact( detail::_get_context(), result.data + 1, &recid, &secp_sig);
        } while( require_canonical && !public_key::is_canonical( result ) );

        result.begin()[0] = 27 + 4 + recid;
        return result;
    }

}}
