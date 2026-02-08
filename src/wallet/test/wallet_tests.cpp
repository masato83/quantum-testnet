// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/types.h>
#include <policy/policy.h>
#include <psbt.h>
#include <rpc/server.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <future>
#include <memory>
#include <regex>
#include <set>
#include <vector>

using node::MAX_BLOCKFILE_SIZE;

namespace wallet {

// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
static_assert(WALLET_INCREMENTAL_RELAY_FEE >= DEFAULT_INCREMENTAL_RELAY_FEE, "wallet incremental fee is smaller than default incremental relay fee");

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(from.vout[index].nValue - DEFAULT_TRANSACTION_MAXFEE, pubkey);
    mtx.vin.push_back({CTxIn{from.GetHash(), index}});
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout].out = from.vout[index];
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(mtx, &keystore, coins, SIGHASH_ALL, input_errors));
    return mtx;
}

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
    assert(descs.size() == 1);
    auto& desc = descs.at(0);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    Assert(wallet.AddWalletDescriptor(w_desc, provider, "", false));
}

static CExtKey ExtractMasterExtKeyFromDescriptor(const std::string& descriptor)
{
    static const std::regex re{R"(([tx]prv[1-9A-HJ-NP-Za-km-z]+))"};
    std::smatch match;
    if (!std::regex_search(descriptor, match, re) || match.size() < 2) {
        throw std::runtime_error("Could not find extended private key in descriptor string");
    }
    CExtKey key = DecodeExtKey(match[1].str());
    if (!key.key.IsValid()) {
        throw std::runtime_error("Failed to decode extended private key from descriptor string");
    }
    return key;
}

BOOST_FIXTURE_TEST_CASE(update_non_range_descriptor, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        auto key{GenerateRandomKey()};
        auto desc_str{"combo(" + EncodeSecret(key) + ")"};
        FlatSigningProvider provider;
        std::string error;
        auto descs{Parse(desc_str, provider, error, /* require_checksum=*/ false)};
        auto& desc{descs.at(0)};
        WalletDescriptor w_desc{std::move(desc), 0, 0, 0, 0};
        BOOST_CHECK(wallet.AddWalletDescriptor(w_desc, provider, "", false));
        // Wallet should update the non-range descriptor successfully
        BOOST_CHECK(wallet.AddWalletDescriptor(w_desc, provider, "", false));
    }
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Verify ScanForWalletTransactions fails to read an unknown start block.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/{}, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(newTip->nHeight, newTip->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        std::chrono::steady_clock::time_point fake_time;
        reserver.setNow([&] { fake_time += 60s; return fake_time; });
        reserver.reserve();

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(!locator.IsNull() && locator.vHave.front() == newTip->GetBlockHash());
        }

        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/true);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 100 * COIN);

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(!locator.IsNull() && locator.vHave.front() == newTip->GetBlockHash());
        }
    }

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 50 * COIN);
    }

    // Prune the remaining block file.
    {
        LOCK(cs_main);
        file_number = newTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }
}

// This test verifies that wallet settings can be added and removed
// concurrently, ensuring no race conditions occur during either process.
BOOST_FIXTURE_TEST_CASE(write_wallet_settings_concurrently, TestingSetup)
{
    auto chain = m_node.chain.get();
    const auto NUM_WALLETS{5};

    // Since we're counting the number of wallets, ensure we start without any.
    BOOST_REQUIRE(chain->getRwSetting("wallet").isNull());

    const auto& check_concurrent_wallet = [&](const auto& settings_function, int num_expected_wallets) {
        std::vector<std::thread> threads;
        threads.reserve(NUM_WALLETS);
        for (auto i{0}; i < NUM_WALLETS; ++i) threads.emplace_back(settings_function, i);
        for (auto& t : threads) t.join();

        auto wallets = chain->getRwSetting("wallet");
        BOOST_CHECK_EQUAL(wallets.getValues().size(), num_expected_wallets);
    };

    // Add NUM_WALLETS wallets concurrently, ensure we end up with NUM_WALLETS stored.
    check_concurrent_wallet([&chain](int i) {
        Assert(AddWalletSetting(*chain, strprintf("wallet_%d", i)));
    },
                            /*num_expected_wallets=*/NUM_WALLETS);

    // Remove NUM_WALLETS wallets concurrently, ensure we end up with 0 wallets.
    check_concurrent_wallet([&chain](int i) {
        Assert(RemoveWalletSetting(*chain, strprintf("wallet_%d", i)));
    },
                            /*num_expected_wallets=*/0);
}

static int64_t AddTx(ChainstateManager& chainman, CWallet& wallet, uint32_t lockTime, int64_t mockTime, int64_t blockTime)
{
    CMutableTransaction tx;
    TxState state = TxStateInactive{};
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LOCK(cs_main);
        auto inserted = chainman.BlockIndex().emplace(std::piecewise_construct, std::make_tuple(GetRandHash()), std::make_tuple());
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
        state = TxStateConfirmed{hash, block->nHeight, /*index=*/0};
    }
    return wallet.AddToWallet(MakeTransactionRef(tx), state, [&](CWalletTx& wtx, bool /* new_tx */) {
        // Assign wtx.m_state to simplify test and avoid the need to simulate
        // reorg events. Without this, AddToWallet asserts false when the same
        // transaction is confirmed in different blocks.
        wtx.m_state = state;
        return true;
    })->nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 5, 50, 600), 300);
}

void TestLoadWallet(const std::string& name, DatabaseFormat format, std::function<void(std::shared_ptr<CWallet>)> f)
{
    node::NodeContext node;
    auto chain{interfaces::MakeChain(node)};
    DatabaseOptions options;
    options.require_format = format;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database{MakeWalletDatabase(name, options, status, error)};
    auto wallet{std::make_shared<CWallet>(chain.get(), "", std::move(database))};
    BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, f(wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadReceiveRequests, TestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("receive-requests-%i", format)};
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), true));
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(ScriptHash(), true));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "0", "val_rr00"));
            BOOST_CHECK(wallet->EraseAddressReceiveRequest(batch, PKHash(), "0"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr10"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr11"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, ScriptHash(), "2", "val_rr20"));
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11", "val_rr20"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
            RunWithinTxn(wallet->GetDatabase(), /*process_desc=*/"test", [](WalletBatch& batch){
                BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), false));
                BOOST_CHECK(batch.EraseAddressData(ScriptHash()));
                return true;
            });
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
        });
    }
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    ListCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, dummy);
            BOOST_CHECK(res);
            tx = res->tx;
        }
        wallet->CommitTransaction(tx, {}, {});
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK(wallet->cs_wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoinsTest, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(50 * COIN, WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet).GetTotalAmount()));

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{PubKeyDestination{{}}, 1 * COIN, /*subtract_fee=*/false});
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoins(*wallet).Size(), 2U);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(coin.outpoint, /*persist=*/false);
        }
    }
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoins(*wallet).Size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

void TestCoinsResult(ListCoinsTest& context, OutputType out_type, CAmount amount,
                     std::map<OutputType, size_t>& expected_coins_sizes)
{
    LOCK(context.wallet->cs_wallet);
    util::Result<CTxDestination> dest = Assert(context.wallet->GetNewDestination(out_type, ""));
    CWalletTx& wtx = context.AddTx(CRecipient{*dest, amount, /*fSubtractFeeFromAmount=*/true});
    CoinFilterParams filter;
    filter.skip_locked = false;
    CoinsResult available_coins = AvailableCoins(*context.wallet, nullptr, std::nullopt, filter);
    // Lock outputs so they are not spent in follow-up transactions
    for (uint32_t i = 0; i < wtx.tx->vout.size(); i++) context.wallet->LockCoin({wtx.GetHash(), i}, /*persist=*/false);
    for (const auto& [type, size] : expected_coins_sizes) BOOST_CHECK_EQUAL(size, available_coins.coins[type].size());
}

BOOST_FIXTURE_TEST_CASE(BasicOutputTypesTest, ListCoinsTest)
{
    std::map<OutputType, size_t> expected_coins_sizes;
    for (const auto& out_type : OUTPUT_TYPES) { expected_coins_sizes[out_type] = 0U; }

    // Verify our wallet has one usable coinbase UTXO before starting
    // This UTXO is a P2PK, so it should show up in the Other bucket
    expected_coins_sizes[OutputType::UNKNOWN] = 1U;
    CoinsResult available_coins = WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet));
    BOOST_CHECK_EQUAL(available_coins.Size(), expected_coins_sizes[OutputType::UNKNOWN]);
    BOOST_CHECK_EQUAL(available_coins.coins[OutputType::UNKNOWN].size(), expected_coins_sizes[OutputType::UNKNOWN]);

    // We will create a self transfer for each of the OutputTypes and
    // verify it is put in the correct bucket after running GetAvailablecoins
    //
    // For each OutputType, We expect 2 UTXOs in our wallet following the self transfer:
    //   1. One UTXO as the recipient
    //   2. One UTXO from the change, due to payment address matching logic

    for (const auto& out_type : OUTPUT_TYPES) {
        if (out_type == OutputType::UNKNOWN) continue;
        expected_coins_sizes[out_type] = 2U;
        TestCoinsResult(*this, out_type, 1 * COIN, expected_coins_sizes);
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    FillableSigningProvider keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

bool malformed_descriptor(std::ios_base::failure e)
{
    std::string s(e.what());
    return s.find("Missing checksum") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(wallet_descriptor_test, BasicTestingSetup)
{
    std::vector<unsigned char> malformed_record;
    VectorWriter vw{malformed_record, 0};
    vw << std::string("notadescriptor");
    vw << uint64_t{0};
    vw << int32_t{0};
    vw << int32_t{0};
    vw << int32_t{1};

    SpanReader vr{malformed_record};
    WalletDescriptor w_desc;
    BOOST_CHECK_EXCEPTION(vr >> w_desc, std::ios_base::failure, malformed_descriptor);
}

//! Test CWallet::CreateNew() and its behavior handling potential race
//! conditions if it's called the same time an incoming transaction shows up in
//! the mempool or a new block.
//!
//! It isn't possible to verify there aren't race condition in every case, so
//! this test just checks two specific cases and ensures that timing of
//! notifications in these cases doesn't prevent the wallet from detecting
//! transactions.
//!
//! In the first case, block and mempool transactions are created before the
//! wallet is loaded, but notifications about these transactions are delayed
//! until after it is loaded. The notifications are superfluous in this case, so
//! the test verifies the transactions are detected before they arrive.
//!
//! In the second case, block and mempool transactions are created after the
//! wallet rescan and notifications are immediately synced, to verify the wallet
//! must already have a handler in place for them, and there's no gap after
//! rescanning where new transactions in new blocks could be lost.
BOOST_FIXTURE_TEST_CASE(CreateWallet, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    // Create new wallet with known key and unload it.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);
    TestUnloadWallet(std::move(wallet));


    // Add log hook to detect AddToWallet events from rescans, blockConnected,
    // and transactionAddedToMempool notifications
    int addtx_count = 0;
    DebugLogHelper addtx_counter("[default wallet] AddToWallet", [&](const std::string* s) {
        if (s) ++addtx_count;
        return false;
    });


    bool rescan_completed = false;
    DebugLogHelper rescan_check("[default wallet] Rescan completed", [&](const std::string* s) {
        if (s) rescan_completed = true;
        return false;
    });


    // Block the queue to prevent the wallet receiving blockConnected and
    // transactionAddedToMempool notifications, and create block and mempool
    // transactions paying to the wallet
    std::promise<void> promise;
    m_node.validation_signals->CallFunctionInValidationInterfaceQueue([&promise] {
        promise.get_future().wait();
    });
    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto mempool_tx = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, node::TxBroadcast::MEMPOOL_NO_BROADCAST, error));


    // Reload wallet and make sure new transactions are detected despite events
    // being blocked
    // Loading will also ask for current mempool transactions
    wallet = TestLoadWallet(context);
    BOOST_CHECK(rescan_completed);
    // AddToWallet events for block_tx and mempool_tx (x2)
    BOOST_CHECK_EQUAL(addtx_count, 3);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->mapWallet.contains(block_tx.GetHash()));
        BOOST_CHECK(wallet->mapWallet.contains(mempool_tx.GetHash()));
    }


    // Unblock notification queue and make sure stale blockConnected and
    // transactionAddedToMempool events are processed
    promise.set_value();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // AddToWallet events for block_tx and mempool_tx events are counted a
    // second time as the notification queue is processed
    BOOST_CHECK_EQUAL(addtx_count, 5);


    TestUnloadWallet(std::move(wallet));


    // Load wallet again, this time creating new block and mempool transactions
    // paying to the wallet as the wallet finishes loading and syncing the
    // queue so the events have to be handled immediately. Releasing the wallet
    // lock during the sync is a little artificial but is needed to avoid a
    // deadlock during the sync and simulates a new block notification happening
    // as soon as possible.
    addtx_count = 0;
    auto handler = HandleLoadWallet(context, [&](std::unique_ptr<interfaces::Wallet> wallet) {
            BOOST_CHECK(rescan_completed);
            m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            block_tx = TestSimpleSpend(*m_coinbase_txns[2], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            mempool_tx = TestSimpleSpend(*m_coinbase_txns[3], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, node::TxBroadcast::MEMPOOL_NO_BROADCAST, error));
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
        });
    wallet = TestLoadWallet(context);
    // Since mempool transactions are requested at the end of loading, there will
    // be 2 additional AddToWallet calls, one from the previous test, and a duplicate for mempool_tx
    BOOST_CHECK_EQUAL(addtx_count, 2 + 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->mapWallet.contains(block_tx.GetHash()));
        BOOST_CHECK(wallet->mapWallet.contains(mempool_tx.GetHash()));
    }


    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletWithoutChain, BasicTestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_CHECK(wallet);
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHSignFromWalletDescriptor, TestChain100Setup)
{
    // End-to-end sign+verify roundtrip for a wallet-owned P2TSH UTXO.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    CTxDestination dest;
    {
        LOCK(wallet->cs_wallet);
        dest = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    }
    const CScript script_pubkey = GetScriptForDestination(dest);

    CMutableTransaction tx_credit;
    tx_credit.vout.emplace_back(1000, script_pubkey);

    CMutableTransaction tx_spend;
    tx_spend.vin.emplace_back(tx_credit.GetHash(), 0);
    tx_spend.vout.emplace_back(500, CScript{} << OP_TRUE);

    std::map<COutPoint, Coin> coins;
    Coin coin;
    coin.out = tx_credit.vout[0];
    coin.nHeight = 1;
    coin.fCoinBase = false;
    coins.emplace(tx_spend.vin[0].prevout, std::move(coin));

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(wallet->SignTransaction(tx_spend, coins, SIGHASH_DEFAULT, input_errors));

    const CTransaction tx_spend_const{tx_spend};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend_const, std::vector<CTxOut>{tx_credit.vout[0]}, true);

    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    const bool ok = VerifyScript(tx_spend.vin[0].scriptSig, tx_credit.vout[0].scriptPubKey, &tx_spend.vin[0].scriptWitness,
                                 SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_QUANTUM,
                                 TransactionSignatureChecker(&tx_spend_const, 0, tx_credit.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
                                 &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHSignFinalizePSBTFromWalletDescriptor, TestChain100Setup)
{
    // Ensure PSBT signing/finalization works for P2TSH outputs from the wallet descriptor.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    CTxDestination dest;
    {
        LOCK(wallet->cs_wallet);
        dest = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    }
    const CScript script_pubkey = GetScriptForDestination(dest);

    CMutableTransaction tx_credit;
    tx_credit.vout.emplace_back(1000, script_pubkey);

    CMutableTransaction tx_spend;
    tx_spend.vin.emplace_back(tx_credit.GetHash(), 0);
    tx_spend.vout.emplace_back(500, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx_spend};
    psbt.inputs[0].witness_utxo = tx_credit.vout[0];

    bool complete{false};
    size_t n_signed{0};
    const auto error = wallet->FillPSBT(psbt, complete, std::nullopt, /*sign=*/true, /*bip32derivs=*/true, &n_signed, /*finalize=*/true);
    BOOST_CHECK(!error);
    BOOST_CHECK_EQUAL(n_signed, 1U);
    BOOST_CHECK(complete);
    BOOST_CHECK(PSBTInputSigned(psbt.inputs[0]));

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(FinalizePSBT(psbt));

    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted));

    const CTransaction extracted_tx{extracted};
    PrecomputedTransactionData extracted_txdata;
    extracted_txdata.Init(extracted_tx, std::vector<CTxOut>{tx_credit.vout[0]}, true);

    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    const bool ok = VerifyScript(extracted.vin[0].scriptSig, tx_credit.vout[0].scriptPubKey, &extracted.vin[0].scriptWitness,
                                 SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_QUANTUM,
                                 TransactionSignatureChecker(&extracted_tx, 0, tx_credit.vout[0].nValue, extracted_txdata, MissingDataBehavior::ASSERT_FAIL),
                                 &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHSignHashSingleCommitsOnlyMatchingOutput, TestChain100Setup)
{
    // SIGHASH_SINGLE should commit the signature to the output with the same index as the input.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    CTxDestination dest;
    {
        LOCK(wallet->cs_wallet);
        dest = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    }
    const CScript script_pubkey = GetScriptForDestination(dest);

    CMutableTransaction tx_credit;
    tx_credit.vout.emplace_back(2000, script_pubkey);

    CMutableTransaction tx_spend;
    tx_spend.vin.emplace_back(tx_credit.GetHash(), 0);
    tx_spend.vout.emplace_back(1200, CScript{} << OP_TRUE);
    tx_spend.vout.emplace_back(700, CScript{} << OP_TRUE);

    std::map<COutPoint, Coin> coins;
    Coin coin;
    coin.out = tx_credit.vout[0];
    coin.nHeight = 1;
    coin.fCoinBase = false;
    coins.emplace(tx_spend.vin[0].prevout, std::move(coin));

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(wallet->SignTransaction(tx_spend, coins, SIGHASH_SINGLE, input_errors));

    auto verify_signed_input = [&](const CMutableTransaction& spend, ScriptError& err) {
        const CTransaction spend_const{spend};
        PrecomputedTransactionData txdata;
        txdata.Init(spend_const, std::vector<CTxOut>{tx_credit.vout[0]}, true);
        return VerifyScript(spend.vin[0].scriptSig, tx_credit.vout[0].scriptPubKey, &spend.vin[0].scriptWitness,
                            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_QUANTUM,
                            TransactionSignatureChecker(&spend_const, 0, tx_credit.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
                            &err);
    };

    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(verify_signed_input(tx_spend, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Changing a non-matching output should not invalidate a SIGHASH_SINGLE signature.
    CMutableTransaction tx_change_other_output{tx_spend};
    tx_change_other_output.vout[1].nValue -= 1;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(verify_signed_input(tx_change_other_output, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Changing the matching output must invalidate the signature.
    CMutableTransaction tx_change_matching_output{tx_spend};
    tx_change_matching_output.vout[0].nValue -= 1;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!verify_signed_input(tx_change_matching_output, err));
    BOOST_CHECK_NE(err, SCRIPT_ERR_OK);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHAddressRestoredFromHDMasterKey, TestChain100Setup)
{
    // Reconstruct descriptor managers from the HD master key and check first P2TSH address matches.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet_original = TestCreateWallet(context);

    CExtKey master_key;
    CTxDestination first_p2tsh_address;
    {
        LOCK(wallet_original->cs_wallet);
        auto* bech32_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet_original->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
        BOOST_REQUIRE(bech32_spkm);

        std::string priv_desc;
        BOOST_REQUIRE(bech32_spkm->GetDescriptorString(priv_desc, /*priv=*/true));
        master_key = ExtractMasterExtKeyFromDescriptor(priv_desc);

        first_p2tsh_address = *Assert(wallet_original->GetNewDestination(OutputType::P2TSH, ""));
    }

    auto wallet_restored = TestCreateWallet(CreateMockableWalletDatabase(), context, WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
    {
        LOCK(wallet_restored->cs_wallet);
        WalletBatch batch(wallet_restored->GetDatabase());
        BOOST_REQUIRE(batch.TxnBegin());
        wallet_restored->SetupDescriptorScriptPubKeyMans(batch, master_key);
        BOOST_REQUIRE(batch.TxnCommit());
    }

    CTxDestination restored_first_p2tsh_address;
    {
        LOCK(wallet_restored->cs_wallet);
        restored_first_p2tsh_address = *Assert(wallet_restored->GetNewDestination(OutputType::P2TSH, ""));
    }

    BOOST_CHECK_EQUAL(EncodeDestination(first_p2tsh_address), EncodeDestination(restored_first_p2tsh_address));

    TestUnloadWallet(std::move(wallet_restored));
    TestUnloadWallet(std::move(wallet_original));
}

BOOST_FIXTURE_TEST_CASE(P2TSHSelectedCoinControlAvailableBalance, TestChain100Setup)
{
    // Selected-input accounting and tx creation should work with a P2TSH receive output.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    const CTxDestination receive_dest = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    const CScript receive_script = GetScriptForDestination(receive_dest);

    CMutableTransaction spend = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, receive_script);
    CreateAndProcessBlock({spend}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const COutPoint outpoint{spend.GetHash(), 0};
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->mapWallet.contains(spend.GetHash()));
        BOOST_REQUIRE(wallet->GetTXO(outpoint).has_value());
    }

    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = false;
    coin_control.Select(outpoint);
    coin_control.m_feerate = CFeeRate(1000);
    coin_control.fOverrideFeeRate = true;

    FastRandomContext rng;
    CoinSelectionParams params(rng);
    {
        LOCK(wallet->cs_wallet);
        const auto preset_inputs = *Assert(FetchSelectedInputs(*wallet, coin_control, params));
        BOOST_CHECK_EQUAL(preset_inputs.total_amount, spend.vout[0].nValue);
    }

    // Ensure fee estimation succeeds with selected P2TSH inputs.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::P2TSH, "")),
                                        1 * COIN, /*fSubtractFeeFromAmount=*/false}};
    auto tx_res = CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control);
    BOOST_REQUIRE(tx_res);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHSpendReceiveAndChangeFromCoinControl, TestChain100Setup)
{
    // Exercise coin control spend flow when both receive and change outputs are P2TSH.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    // Ensure we have at least two mature coinbase UTXOs available for spending.
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // Create two wallet UTXOs:
    // - one from the receive (external) keypool
    // - one change (internal) output created by the wallet
    const CScript receive_script_1 = GetScriptForDestination(*Assert(wallet->GetNewDestination(OutputType::P2TSH, "")));
    const CScript receive_script_2 = GetScriptForDestination(*Assert(wallet->GetNewDestination(OutputType::P2TSH, "")));
    CMutableTransaction fund_1 = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, receive_script_1);
    CMutableTransaction fund_2 = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, receive_script_2);
    CreateAndProcessBlock({fund_1, fund_2}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const COutPoint receive_outpoint{fund_1.GetHash(), 0};
    const COutPoint fund_outpoint{fund_2.GetHash(), 0};
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetTXO(receive_outpoint).has_value());
        BOOST_REQUIRE(wallet->GetTXO(fund_outpoint).has_value());
    }

    // Create a transaction that spends the second UTXO but leaves P2TSH change.
    CCoinControl cc_make_change;
    cc_make_change.m_allow_other_inputs = false;
    cc_make_change.Select(fund_outpoint);
    cc_make_change.m_change_type = OutputType::P2TSH;
    cc_make_change.m_feerate = CFeeRate(1000);
    cc_make_change.fOverrideFeeRate = true;

    const CTxDestination dest_nochange = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    std::vector<CRecipient> recipients_make_change{{dest_nochange, 1 * COIN, /*fSubtractFeeFromAmount=*/false}};
    auto tx_with_change_res = CreateTransaction(*wallet, recipients_make_change, /*change_pos=*/std::nullopt, cc_make_change);
    BOOST_REQUIRE(tx_with_change_res);
    BOOST_REQUIRE(tx_with_change_res->change_pos.has_value());

    const CTransactionRef& tx_with_change = tx_with_change_res->tx;
    const unsigned int change_pos = *tx_with_change_res->change_pos;
    BOOST_REQUIRE(change_pos < tx_with_change->vout.size());

    // Mine the transaction so the change output becomes available.
    CMutableTransaction tx_with_change_mut{*tx_with_change};
    CreateAndProcessBlock({tx_with_change_mut}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const COutPoint change_outpoint{tx_with_change->GetHash(), change_pos};
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetTXO(change_outpoint).has_value());
    }

    // Now try to spend *both* the receive and change outputs together with coin control
    // (mirrors GUI behavior when selecting both UTXOs in coin control).
    CCoinControl cc_spend_both;
    cc_spend_both.m_allow_other_inputs = false;
    cc_spend_both.Select(receive_outpoint);
    cc_spend_both.Select(change_outpoint);
    cc_spend_both.m_change_type = OutputType::P2TSH;
    cc_spend_both.m_feerate = CFeeRate(1000);
    cc_spend_both.fOverrideFeeRate = true;

    const CTxDestination dest_spend = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    std::vector<CRecipient> recipients_spend{{dest_spend, 5000, /*fSubtractFeeFromAmount=*/false}};
    auto spend_both_res = CreateTransaction(*wallet, recipients_spend, /*change_pos=*/std::nullopt, cc_spend_both);
    BOOST_REQUIRE(spend_both_res);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHMultipleReceiveAndChangeAddresses, TestChain100Setup)
{
    // Receive/change derivation should produce unique P2TSH addresses across reloads.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    const CTxDestination recv_1 = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    const CTxDestination recv_2 = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    const CTxDestination change_1 = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));
    const CTxDestination change_2 = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));

    BOOST_CHECK(recv_1 != recv_2);
    BOOST_CHECK(change_1 != change_2);
    BOOST_CHECK(recv_1 != change_1);
    BOOST_CHECK(recv_2 != change_2);

    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(recv_1));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(recv_2));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_1));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_2));

    TestUnloadWallet(std::move(wallet));

    wallet = TestLoadWallet(context);
    const CTxDestination recv_3 = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
    const CTxDestination change_3 = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));

    BOOST_CHECK(recv_3 != recv_1);
    BOOST_CHECK(recv_3 != recv_2);
    BOOST_CHECK(change_3 != change_1);
    BOOST_CHECK(change_3 != change_2);
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(recv_3));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_3));

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHEncryptedWalletCanGetAddressesLocked, TestChain100Setup)
{
    // With a tiny keypool, locked encrypted wallets can use cached P2TSH entries but cannot top up.
    m_args.ForceSetArg("-keypool", "1");

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    const SecureString passphrase{"p2tsh-test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->IsLocked());

    DescriptorScriptPubKeyMan* receive_spkm;
    DescriptorScriptPubKeyMan* change_spkm;
    {
        LOCK(wallet->cs_wallet);
        receive_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2TSH, /*internal=*/false));
        change_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2TSH, /*internal=*/true));
        BOOST_REQUIRE(receive_spkm);
        BOOST_REQUIRE(change_spkm);
        BOOST_CHECK(receive_spkm->CanGetAddresses(/*internal=*/false));
        BOOST_CHECK(change_spkm->CanGetAddresses(/*internal=*/true));
    }

    {
        LOCK(wallet->cs_wallet);
        // First receive/change addresses are available from the pre-generated cache.
        const CTxDestination receive_1 = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
        const CTxDestination change_1 = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(receive_1));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_1));

        // Next addresses require top-up and should fail while the wallet is locked.
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::P2TSH, ""));
        BOOST_CHECK(!wallet->GetNewChangeDestination(OutputType::P2TSH));
    }

    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        // Unlocking restores private key access, so top-up and derivation continue.
        const CTxDestination receive_2 = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
        const CTxDestination change_2 = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(receive_2));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_2));
    }
    BOOST_REQUIRE(wallet->Lock());

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHReserveReturnReuse, TestChain100Setup)
{
    // Returning a reserved P2TSH change destination should make it reusable; keeping should advance.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    CTxDestination addr_returned;
    CTxDestination addr_reused;
    CTxDestination addr_next;
    {
        LOCK(wallet->cs_wallet);

        ReserveDestination reserve(wallet.get(), OutputType::P2TSH);
        addr_returned = *Assert(reserve.GetReservedDestination(/*internal=*/true));
        reserve.ReturnDestination();

        ReserveDestination reserve_reuse(wallet.get(), OutputType::P2TSH);
        addr_reused = *Assert(reserve_reuse.GetReservedDestination(/*internal=*/true));
        reserve_reuse.KeepDestination();

        ReserveDestination reserve_next(wallet.get(), OutputType::P2TSH);
        addr_next = *Assert(reserve_next.GetReservedDestination(/*internal=*/true));
        reserve_next.ReturnDestination();
    }

    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(addr_returned));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(addr_reused));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(addr_next));
    BOOST_CHECK_EQUAL(EncodeDestination(addr_returned), EncodeDestination(addr_reused));
    BOOST_CHECK(EncodeDestination(addr_next) != EncodeDestination(addr_reused));

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2TSHCanGetAddressesAfterReloadLocked, TestChain100Setup)
{
    // After reload in locked state, cached P2TSH addresses remain usable but top-up requires unlock.
    m_args.ForceSetArg("-keypool", "1");

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);

    const SecureString passphrase{"p2tsh-reload-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    TestUnloadWallet(std::move(wallet));

    wallet = TestLoadWallet(context);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE(wallet->IsLocked());

    DescriptorScriptPubKeyMan* receive_spkm;
    DescriptorScriptPubKeyMan* change_spkm;
    {
        LOCK(wallet->cs_wallet);
        receive_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2TSH, /*internal=*/false));
        change_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2TSH, /*internal=*/true));
        BOOST_REQUIRE(receive_spkm);
        BOOST_REQUIRE(change_spkm);
        BOOST_CHECK(receive_spkm->CanGetAddresses(/*internal=*/false));
        BOOST_CHECK(change_spkm->CanGetAddresses(/*internal=*/true));
    }

    {
        LOCK(wallet->cs_wallet);
        // Cached receive/change addresses are still available immediately after reload.
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2TSH, ""));
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2TSH));

        // Additional derivation fails while locked because no private keys are available for top-up.
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::P2TSH, ""));
        BOOST_CHECK(!wallet->GetNewChangeDestination(OutputType::P2TSH));
    }

    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        // Unlock allows on-demand top-up and address generation to continue.
        const CTxDestination receive_after_unlock = *Assert(wallet->GetNewDestination(OutputType::P2TSH, ""));
        const CTxDestination change_after_unlock = *Assert(wallet->GetNewChangeDestination(OutputType::P2TSH));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(receive_after_unlock));
        BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(change_after_unlock));
    }
    BOOST_REQUIRE(wallet->Lock());

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(RemoveTxs, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);

    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        auto block_hash = block_tx.GetHash();
        auto prev_tx = m_coinbase_txns[0];

        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK(wallet->mapWallet.contains(block_hash));

        std::vector<Txid> vHashIn{ block_hash };
        BOOST_CHECK(wallet->RemoveTxs(vHashIn));

        BOOST_CHECK(!wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK(!wallet->mapWallet.contains(block_hash));
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
