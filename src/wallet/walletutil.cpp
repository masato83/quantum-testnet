// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <key_io.h>
#include <logging.h>

namespace wallet {
fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

static uint32_t GetCoinType()
{
    // Keep parity with existing descriptor derivation coin type handling.
    return Params().IsTestChain() ? 1 : 0;
}

bool DeriveWalletMLDSAKey(const CKey& hd_master_key, bool internal, uint32_t index, std::vector<unsigned char>& mldsa_pubkey, std::vector<unsigned char>& mldsa_seckey)
{
    mldsa_pubkey.assign(mldsa::MLDSA87_PUBLICKEY_SIZE, 0);
    mldsa_seckey.assign(mldsa::MLDSA87_SECRETKEY_SIZE, 0);

    // Derive an MLDSA seed deterministically from the wallet HD master key, branch, and index.
    CHMAC_SHA256 hmac(reinterpret_cast<const unsigned char*>(hd_master_key.begin()), hd_master_key.size());
    static constexpr unsigned char TAG[] = {'M', 'L', 'D', 'S', 'A', '_', 'W', 'A', 'L', 'L', 'E', 'T', '_', 'V', '1'};
    hmac.Write(TAG, sizeof(TAG));
    const uint32_t coin_type = GetCoinType();
    uint8_t serialized_u32[4];
    WriteBE32(serialized_u32, coin_type);
    hmac.Write(serialized_u32, sizeof(serialized_u32));
    const unsigned char internal_byte = internal ? 1 : 0;
    hmac.Write(&internal_byte, 1);
    WriteBE32(serialized_u32, index);
    hmac.Write(serialized_u32, sizeof(serialized_u32));

    std::array<unsigned char, mldsa::MLDSA_SEED_SIZE> seed;
    hmac.Finalize(seed.data());
    return mldsa::KeypairFromSeed(seed, mldsa_pubkey, mldsa_seckey);
}

bool DeriveWalletMLDSAKey(const CKey& hd_master_key, bool internal, std::vector<unsigned char>& mldsa_pubkey, std::vector<unsigned char>& mldsa_seckey)
{
    return DeriveWalletMLDSAKey(hd_master_key, internal, 0, mldsa_pubkey, mldsa_seckey);
}

WalletDescriptor GenerateWalletDescriptor(const CExtPubKey& master_key, const OutputType& addr_type, bool internal, const std::optional<std::vector<unsigned char>>& mldsa_pubkey)
{
    int64_t creation_time = GetTime();

    std::string xpub = EncodeExtPubKey(master_key);

    // Build descriptor string
    std::string desc_prefix;
    std::string desc_suffix = "/*)";
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(" + xpub + "/44h";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(" + xpub + "/49h";
        desc_suffix += ")";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(" + xpub + "/84h";
        break;
    }
    case OutputType::BECH32M: {
        desc_prefix = "tr(" + xpub + "/86h";
        break;
    }
    case OutputType::P2TSH: {
        if (!mldsa_pubkey || mldsa_pubkey->size() != mldsa::MLDSA87_PUBLICKEY_SIZE) {
            throw std::runtime_error("P2TSH descriptor generation requires an MLDSA public key");
        }
        const std::string desc_str = "mldsa(" + HexStr(*mldsa_pubkey) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
        if (desc.empty()) {
            throw std::runtime_error("Failed to parse generated mldsa descriptor: " + error);
        }
        WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
        return w_desc;
    }
    case OutputType::UNKNOWN: {
        // We should never have a DescriptorScriptPubKeyMan for an UNKNOWN OutputType,
        // so if we get to this point something is wrong
        assert(false);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(!desc_prefix.empty());

    // Mainnet derives at 0', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1h";
    } else {
        desc_prefix += "/0h";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0h" + internal_path + desc_suffix;

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

} // namespace wallet
