// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/mldsa.h>

#include <mldsa_native.h>

#include <array>
#include <cstring>
#include <vector>

namespace mldsa {
namespace {

bool BuildPre(std::span<const unsigned char> context, std::vector<unsigned char>& pre)
{
    if (context.size() > 255) return false;
    pre.assign(context.size() + 2, 0);
    pre[1] = static_cast<unsigned char>(context.size());
    if (!context.empty()) {
        std::memcpy(pre.data() + 2, context.data(), context.size());
    }
    return true;
}

} // namespace

bool KeypairFromSeed(std::span<const unsigned char> seed,
                     std::span<unsigned char> pubkey,
                     std::span<unsigned char> seckey)
{
    if (seed.size() != MLDSA_SEED_SIZE) return false;
    if (pubkey.size() != MLDSA87_PUBLICKEY_SIZE) return false;
    if (seckey.size() != MLDSA87_SECRETKEY_SIZE) return false;
    return MLD_API_NAMESPACE(keypair_internal)(pubkey.data(), seckey.data(), seed.data()) == 0;
}

bool PubkeyFromSeckey(std::span<const unsigned char> seckey,
                      std::span<unsigned char> pubkey)
{
    if (pubkey.size() != MLDSA87_PUBLICKEY_SIZE) return false;
    if (seckey.size() != MLDSA87_SECRETKEY_SIZE) return false;
    return MLD_API_NAMESPACE(pk_from_sk)(pubkey.data(), seckey.data()) == 0;
}

bool SignDeterministic(std::span<const unsigned char> msg,
                       std::span<const unsigned char> context,
                       std::span<const unsigned char> seckey,
                       std::span<unsigned char> signature)
{
    if (seckey.size() != MLDSA87_SECRETKEY_SIZE) return false;
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) return false;

    std::vector<unsigned char> pre;
    if (!BuildPre(context, pre)) return false;

    std::array<unsigned char, MLDSA_RNDBYTES> rnd{};
    size_t siglen = 0;
    const int ret = MLD_API_NAMESPACE(signature_internal)(
        signature.data(), &siglen, msg.data(), msg.size(), pre.data(), pre.size(),
        rnd.data(), seckey.data(), /*externalmu=*/0);
    return ret == 0 && siglen == signature.size();
}

bool Verify(std::span<const unsigned char> signature,
            std::span<const unsigned char> msg,
            std::span<const unsigned char> context,
            std::span<const unsigned char> pubkey)
{
    if (pubkey.size() != MLDSA87_PUBLICKEY_SIZE) return false;
    const unsigned char* ctx_ptr = context.empty() ? nullptr : context.data();
    return MLD_API_NAMESPACE(verify)(signature.data(), signature.size(), msg.data(), msg.size(),
                                     ctx_ptr, context.size(), pubkey.data()) == 0;
}

} // namespace mldsa
