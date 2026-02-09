// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_MLDSA_H
#define BITCOIN_CRYPTO_MLDSA_H

#include <cstddef>
#include <span>

namespace mldsa {

constexpr size_t MLDSA87_PUBLICKEY_SIZE = 2592;
constexpr size_t MLDSA87_SECRETKEY_SIZE = 4896;
constexpr size_t MLDSA87_SIGNATURE_SIZE = 4627;
constexpr size_t MLDSA_SEED_SIZE = 32;

bool KeypairFromSeed(std::span<const unsigned char> seed,
                     std::span<unsigned char> pubkey,
                     std::span<unsigned char> seckey);

bool PubkeyFromSeckey(std::span<const unsigned char> seckey,
                      std::span<unsigned char> pubkey);

bool SignDeterministic(std::span<const unsigned char> msg,
                       std::span<const unsigned char> context,
                       std::span<const unsigned char> seckey,
                       std::span<unsigned char> signature);

bool Verify(std::span<const unsigned char> signature,
            std::span<const unsigned char> msg,
            std::span<const unsigned char> context,
            std::span<const unsigned char> pubkey);

} // namespace mldsa

#endif // BITCOIN_CRYPTO_MLDSA_H
