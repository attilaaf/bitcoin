// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include "base58.h"
#include "chain.h"
#include "coins.h"
#include "config.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "dstencode.h"
#include "init.h"
#include "keystore.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "rpc/tojson.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"
#ifdef ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#endif

#include <cstdint>

#include <univalue.h>

typedef std::map<int64_t, int64_t> VoutToValueMap;
typedef std::map<TxId, std::unique_ptr<VoutToValueMap>> TxIdToVoutToValueMap;
typedef std::map<int64_t, std::vector<CTxDestination>> VoutToAddressesMap;

void ScriptPubKeyToJSON(const Config &config, const CScript &scriptPubKey,
                        UniValue &out, bool fIncludeHex) {
    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex) {
        out.push_back(
            Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
    }

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    for (const CTxDestination &addr : addresses) {
        a.push_back(EncodeDestination(addr));
    }

    out.push_back(Pair("addresses", a));
}

void ScriptPubKeyToJSON2(const Config &config, const CScript &scriptPubKey,
                        UniValue &out, bool fIncludeAsm, bool fIncludeHex) {
    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    if (fIncludeAsm) {
        out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    }

    if (fIncludeHex) {
        out.push_back(
            Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
    }

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    for (const CTxDestination &addr : addresses) {
        a.push_back(EncodeDestination(addr));
    }

    out.push_back(Pair("addresses", a));
}

void TxToJSON(const Config &config, const CTransaction &tx,
              const uint256 hashBlock, UniValue &entry) {
    entry.push_back(Pair("txid", tx.GetId().GetHex()));
    entry.push_back(Pair("hash", tx.GetHash().GetHex()));
    entry.push_back(Pair(
        "size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));

    UniValue vin(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn &txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(),
                                                 txin.scriptSig.end())));
        } else {
            in.push_back(Pair("txid", txin.prevout.GetTxId().GetHex()));
            in.push_back(Pair("vout", int64_t(txin.prevout.GetN())));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair(
                "hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
            in.push_back(Pair("n", (int64_t)i));
        }

        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }

    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    int64_t valueOut(0);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut &txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        int64_t voutAmt(txout.nValue.GetSatoshis());
        valueOut += voutAmt;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(config, txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, uint256(), entry);

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(
                    Pair("confirmations",
                         1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            } else {
                entry.push_back(Pair("confirmations", 0));
            }
        }
    }
    // We can only calculate these datas
    if (tx.IsCoinBase()) {
        entry.push_back(Pair("isCoinBase", true));
    }
    // entry.push_back(Pair("valueOut", ValueFromAmount(Amount(valueOut))));
}

void TxToJSON2(const Config &config, const CTransaction &tx,
              const uint256 hashBlock, UniValue &entry, bool fIncludeAsm, bool fIncludeHex) {
    entry.push_back(Pair("txid", tx.GetId().GetHex()));
    entry.push_back(Pair("hash", tx.GetHash().GetHex()));
    entry.push_back(Pair(
        "size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));

    std::set<TxId> txidSet;  // Tracks the txid's that are part of the vins used to compute valueIn and addr
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn &txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (!tx.IsCoinBase()) {
            txidSet.insert(txin.prevout.GetTxId());
        }
    }
    // Fetch all the tx's for the vins
    std::unique_ptr<TxIdToVoutToValueMap> txidToVoutValueMap(new TxIdToVoutToValueMap());
    std::unique_ptr<std::map<TxId, std::unique_ptr<VoutToAddressesMap>>> txidToVoutAddressMap(new std::map<TxId, std::unique_ptr<VoutToAddressesMap>>());
    std::set<TxId>::iterator it = txidSet.begin();

    bool useRegularJSON = false;
    while (it != txidSet.end()) {
        CTransactionRef txInput;
        uint256 hashBlockInputTx;
        if (!GetTransaction(config, *it, txInput, hashBlockInputTx, true)) {
            std::cout << "bitindex_tx_not_found if (!GetTransaction(config, *it, txInput, hashBlockInputTx, true)) {" << std::endl;
            TxToJSON(config, tx, hashBlock, entry);
            return;
        }
        // Build the maps
        for (unsigned int i = 0; i < txInput->vout.size(); i++) {
            const CTxOut &txout = txInput->vout[i];
            auto txidToVoutValueMapIterator = (*txidToVoutValueMap).find(*it);
            auto txidToVoutAddressMapIterator = (*txidToVoutAddressMap).find(*it);
            if (txidToVoutValueMapIterator == (*txidToVoutValueMap).end()) {
                VoutToValueMap* voutValueMap = new VoutToValueMap();
                VoutToAddressesMap* voutAddrMap = new VoutToAddressesMap();
                (*txidToVoutValueMap).insert(std::make_pair(*it, std::unique_ptr<VoutToValueMap>(voutValueMap)));
                (*txidToVoutAddressMap).insert(std::make_pair(*it, std::unique_ptr<VoutToAddressesMap>(voutAddrMap)));
                txidToVoutValueMapIterator = (*txidToVoutValueMap).find(*it);
                txidToVoutAddressMapIterator = (*txidToVoutAddressMap).find(*it);
            }
            auto voutValueMapIterator = txidToVoutValueMapIterator->second->find((int64_t) i);
            if (voutValueMapIterator == txidToVoutValueMapIterator->second->end()) {
                txidToVoutValueMapIterator->second->insert(std::make_pair((int64_t) i, txout.nValue.GetSatoshis()));
                voutValueMapIterator = txidToVoutValueMapIterator->second->find((int64_t) i);
            }
            auto voutAddrMapIterator = txidToVoutAddressMapIterator->second->find((int64_t) i);
            if (voutAddrMapIterator == txidToVoutAddressMapIterator->second->end()) {
                txnouttype type;
                std::vector<CTxDestination> addresses;
                int nRequired;
                if (!ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired)) {
                    // Could not extract, therefore it is not a typical addr
                    std::cout << "ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) " << std::endl;
                }
                txidToVoutAddressMapIterator->second->insert(std::make_pair((int64_t) i, addresses));
            }
        }
        it++;
    }

    int64_t valueIn(0);
    UniValue vin(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn &txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(),
                                                 txin.scriptSig.end())));
        } else {
             // Add address and value info if spentindex enabled
            CSpentIndexValue spentInfo;
            CSpentIndexKey spentKey(txin.prevout.GetTxId(), txin.prevout.GetN());
            if (GetSpentIndex(spentKey, spentInfo)) {
                in.push_back(Pair("value", ValueFromAmount(spentInfo.satoshis)));
                in.push_back(Pair("valueSat", spentInfo.satoshis.GetSatoshis()));
                if (spentInfo.addressType == 1) {
                    // in.push_back(Pair("address", CBitcoinAddress(CKeyID(spentInfo.addressHash)).ToString()));
                } else if (spentInfo.addressType == 2)  {
                   //  in.push_back(Pair("address", CBitcoinAddress(CScriptID(spentInfo.addressHash)).ToString()));
                }
            }

            in.push_back(Pair("txid", txin.prevout.GetTxId().GetHex()));
            in.push_back(Pair("vout", int64_t(txin.prevout.GetN())));
            in.push_back(Pair("n", (int64_t)i));

            UniValue o(UniValue::VOBJ);
            if (fIncludeAsm) {
                o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            }
            if (fIncludeHex) {
                o.push_back(Pair(
                    "hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            }
            in.push_back(Pair("scriptSig", o));
            //
            // Get the "value" vout of the vin
            //
            auto voutValueMap = *((*txidToVoutValueMap).find(txin.prevout.GetTxId())->second);
            const bool isInValueMap = voutValueMap.find(int64_t(txin.prevout.GetN())) != voutValueMap.end();

            if (!isInValueMap) {
                std::cout << "const bool isInValueMap = voutValueMap.find(int64_t(txin.prevout.GetN())) != voutValueMap.end();" << std::endl;
                throw new std::exception();
            }
            auto vinVoutValue = voutValueMap.find(int64_t(txin.prevout.GetN()));
            in.push_back(Pair("valueSat", vinVoutValue->second));
            in.push_back(Pair("value", ValueFromAmount(Amount(vinVoutValue->second))));
            valueIn += vinVoutValue->second;
            // Get the the "addr" from vout of vin
            auto voutAddrMap = *((*txidToVoutAddressMap).find(txin.prevout.GetTxId())->second);
            auto voutAddrMapAddrIterator = voutAddrMap.find(int64_t(txin.prevout.GetN()));
            if (voutAddrMapAddrIterator == voutAddrMap.end()) {
                std::cout << "voutAddrMapAddrIterator == voutAddrMap.end()" << std::endl;
                throw new std::exception();
            }
            auto vinVoutAddr = voutAddrMap.find(int64_t(txin.prevout.GetN()));
            if (vinVoutAddr->second.size()) {
                in.push_back(Pair("addr", EncodeDestination(vinVoutAddr->second.at(0))));
                in.push_back(Pair("address", EncodeDestination(vinVoutAddr->second.at(0))));
            }
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);

    int64_t valueOut(0);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut &txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        int64_t voutAmt(txout.nValue.GetSatoshis());
        valueOut += voutAmt;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("valueSat", txout.nValue.GetSatoshis()));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON2(config, txout.scriptPubKey, o, fIncludeAsm, fIncludeHex);
        out.push_back(Pair("scriptPubKey", o));
        // Add spent information if spentindex is enabled
        CSpentIndexValue spentInfo;
        CSpentIndexKey spentKey(tx.GetHash(), i);
        if (GetSpentIndex(spentKey, spentInfo)) {
            out.push_back(Pair("spentTxId", spentInfo.txid.GetHex()));
            out.push_back(Pair("spentIndex", (int)spentInfo.inputIndex));
            out.push_back(Pair("spentHeight", spentInfo.blockHeight));
        } else {
            UniValue o(UniValue::VType::VNULL);
            out.push_back(Pair("spentTxId", o));
            out.push_back(Pair("spentIndex", o));
            out.push_back(Pair("spentHeight", o));
        }

        vout.push_back(out);
    }

    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(
                    Pair("confirmations",
                         1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            } else {
                entry.push_back(Pair("confirmations", 0));
            }
        }
    } else {
        entry.push_back(Pair("confirmations", 0));
        LOCK(mempool.cs);

        CTxMemPool::txiter it = mempool.mapTx.find(tx.GetId());
        if (it == mempool.mapTx.end()) {
            entry.push_back(Pair("time", 0));
        } else {
            const CTxMemPoolEntry &e = *it;
            entry.push_back(Pair("time", e.GetTime()));
        }
    }
    if (!tx.IsCoinBase()) {
        entry.push_back(Pair("valueIn", ValueFromAmount(Amount(valueIn))));
        entry.push_back(Pair("fees", ValueFromAmount(Amount(valueIn - valueOut))));
    } else {
        entry.push_back(Pair("isCoinBase", true));
    }
    entry.push_back(Pair("valueOut", ValueFromAmount(Amount(valueOut))));

    std::string strHex = EncodeHexTx(tx, RPCSerializationFlags());
    entry.push_back(Pair("rawtx", strHex));
}

static UniValue getrawtransaction(const Config &config,
                                  const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"

            "\nNOTE: By default this function only works for mempool "
            "transactions. If the -txindex option is\n"
            "enabled, it also works for blockchain transactions.\n"
            "DEPRECATED: for now, it also works for transactions with unspent "
            "outputs.\n"

            "\nReturn the raw transaction data.\n"
            "\nIf verbose is 'true', returns an Object with information about "
            "'txid'.\n"
            "If verbose is 'false' or omitted, returns a string that is "
            "serialized, hex-encoded data for 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (bool, optional, default=false) If false, return "
            "a string, otherwise return a json object\n"

            "\nResult (if verbose is not set or set to false):\n"
            "\"data\"      (string) The serialized, hex-encoded data for "
            "'txid'\n"

            "\nResult (if verbose is set to true):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded "
            "data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as "
            "provided)\n"
            "  \"hash\" : \"id\",        (string) The transaction hash "
            "(differs from txid for witness transactions)\n"
            "  \"size\" : n,             (numeric) The serialized transaction "
            "size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " +
            CURRENCY_UNIT +
            "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg "
            "'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"address\"        (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in "
            "seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds "
            "since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getrawtransaction", "\"mytxid\"") +
            HelpExampleCli("getrawtransaction", "\"mytxid\" true") +
            HelpExampleRpc("getrawtransaction", "\"mytxid\", true"));
    }

    LOCK(cs_main);

    TxId txid = TxId(ParseHashV(request.params[0], "parameter 1"));

    // Accept either a bool (true) or a num (>=1) to indicate verbose output.
    bool fVerbose = false;
    if (request.params.size() > 1) {
        if (request.params[1].isNum()) {
            if (request.params[1].get_int() != 0) {
                fVerbose = true;
            }
        } else if (request.params[1].isBool()) {
            if (request.params[1].isTrue()) {
                fVerbose = true;
            }
        } else {
            throw JSONRPCError(
                RPC_TYPE_ERROR,
                "Invalid type provided. Verbose parameter must be a boolean.");
        }
    }

    CTransactionRef tx;
    uint256 hashBlock;
    if (!GetTransaction(config, txid, tx, hashBlock, true)) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            std::string(fTxIndex ? "No such mempool or blockchain transaction"
                                 : "No such mempool transaction. Use -txindex "
                                   "to enable blockchain transaction queries") +
                ". Use gettransaction for wallet transactions.");
    }

    std::string strHex = EncodeHexTx(*tx, RPCSerializationFlags());

    if (!fVerbose) {
        return strHex;
    }

    UniValue result(UniValue::VOBJ);
    // result.push_back(Pair("hex", strHex));
    TxToJSON2(config, *tx, hashBlock, result, true, true);
    return result;
}

static UniValue getrawtransactions(const Config &config,
                                  const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 3 ||
        request.params.size() > 3) {
        throw std::runtime_error(
            "getrawtransactions \"txids\" ( includeAsm ) (includeHex) \n"

            "\nNOTE: By default this function only works for mempool "
            "transactions. If the -txindex option is\n"
            "enabled, it also works for blockchain transactions.\n"
            "DEPRECATED: for now, it also works for transactions with unspent "
            "outputs.\n"

            "\nReturn the raw transactions data.\n"
            "\nIf verbose is 'true', returns an Object with information about "
            "'txids'.\n"
            "If verbose is 'false' or omitted, returns a string that is "
            "serialized, hex-encoded data for 'txid'.\n"

            "\nArguments:\n"
            "1. \"txids\"      (string, required) The transaction id\n"
            "2. noAsm       (bool, optional, default=true) If false, return "
            "ASM, if true then omit the ASM in transactions\n"
            "3. noScript       (bool, optional, default=true) If false, return "
            "script, if true then omit the script in transactions\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded "
            "data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as "
            "provided)\n"
            "  \"hash\" : \"id\",        (string) The transaction hash "
            "(differs from txid for witness transactions)\n"
            "  \"size\" : n,             (numeric) The serialized transaction "
            "size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm (omitted if noAsm=true)\n"
            "         \"hex\": \"hex\"   (string) hex (omitted if noAsm=true)\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " +
            CURRENCY_UNIT +
            "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm (omitted if noAsm=true)\n"
            "         \"hex\" : \"hex\",          (string) the hex (omitted if noAsm=true)\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg "
            "'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"address\"        (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in "
            "seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds "
            "since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getrawtransactions", "[\"mytxid1\", \"mytxid2\"]") +
            HelpExampleCli("getrawtransactions", "[\"mytxid1\"], true false") +
            HelpExampleRpc("getrawtransactions", "[\"mytxid1\", \"mytxid2\"], false false"));
    }

    LOCK(cs_main);

    if (!request.params[0].isArray()) {
        throw JSONRPCError(
        RPC_TYPE_ERROR,
        "Invalid type provided. txids parameter must be an array.");
    }

    bool fIncludeAsm = false;

    if (!request.params[1].isBool()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. IncludeAsm parameter must be a boolean.");
    } else {
        fIncludeAsm = request.params[1].isTrue();
    }

    bool fIncludeHex = false;
    if (!request.params[2].isBool()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. IncludeHex parameter must be a boolean.");
    } else {
        fIncludeHex = request.params[2].isTrue();
    }

    // std::string strHex = EncodeHexTx(*tx, RPCSerializationFlags());
    // Todo, remove data
    // UniValue result(UniValue::VOBJ);
    // result.push_back(Pair("hex", strHex));
    // TxToJSON(config, *tx, hashBlock, result);

    UniValue txsResults(UniValue::VARR);
    // txsResults.push_back(result);
    // For each txid, get the transaction if available and push it back
    UniValue txIdsArray(request.params[0].get_array());
    for (size_t idx = 0; idx < txIdsArray.size(); idx++) {
        const UniValue &p = txIdsArray[idx];
        TxId txid = TxId(ParseHashV(p, "parameter"));
        CTransactionRef tx;
        uint256 hashBlock;
        if (!GetTransaction(config, txid, tx, hashBlock, true)) {
            continue;
        }
        UniValue result(UniValue::VOBJ);
        TxToJSON2(config, *tx, hashBlock, result, fIncludeAsm, fIncludeHex);
        txsResults.push_back(result);
    }
    return txsResults;
}

static UniValue gettxoutproof(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp ||
        (request.params.size() != 1 && request.params.size() != 2)) {
        throw std::runtime_error(
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a "
            "block.\n"
            "\nNOTE: By default this function only works sometimes. This is "
            "when there is an\n"
            "unspent output in the utxo for this transaction. To make it "
            "always work,\n"
            "you need to maintain a transaction index, using the -txindex "
            "command line option or\n"
            "specify the block in which the transaction is included manually "
            "(by blockhash).\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"blockhash\"   (string, optional) If specified, looks for "
            "txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, "
            "hex-encoded data for the proof.\n");
    }

    std::set<TxId> setTxIds;
    TxId oneTxId;
    UniValue txids = request.params[0].get_array();
    for (unsigned int idx = 0; idx < txids.size(); idx++) {
        const UniValue &utxid = txids[idx];
        if (utxid.get_str().length() != 64 || !IsHex(utxid.get_str())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               std::string("Invalid txid ") + utxid.get_str());
        }

        TxId txid(uint256S(utxid.get_str()));
        if (setTxIds.count(txid)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                std::string("Invalid parameter, duplicated txid: ") +
                    utxid.get_str());
        }

        setTxIds.insert(txid);
        oneTxId = txid;
    }

    LOCK(cs_main);

    CBlockIndex *pblockindex = nullptr;

    uint256 hashBlock;
    if (request.params.size() > 1) {
        hashBlock = uint256S(request.params[1].get_str());
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = mapBlockIndex[hashBlock];
    } else {
        // Loop through txids and try to find which block they're in. Exit loop
        // once a block is found.
        for (const auto &txid : setTxIds) {
            const Coin &coin = AccessByTxid(*pcoinsTip, txid);
            if (!coin.IsSpent()) {
                pblockindex = chainActive[coin.GetHeight()];
                break;
            }
        }
    }

    if (pblockindex == nullptr) {
        CTransactionRef tx;
        if (!GetTransaction(config, oneTxId, tx, hashBlock, false) ||
            hashBlock.IsNull()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Transaction not yet in block");
        }

        if (!mapBlockIndex.count(hashBlock)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        }

        pblockindex = mapBlockIndex[hashBlock];
    }

    CBlock block;
    if (!ReadBlockFromDisk(block, pblockindex, config)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    unsigned int ntxFound = 0;
    for (const auto &tx : block.vtx) {
        if (setTxIds.count(tx->GetId())) {
            ntxFound++;
        }
    }

    if (ntxFound != setTxIds.size()) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Not all transactions found in specified or retrieved block");
    }

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock mb(block, setTxIds);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

static UniValue verifytxoutproof(const Config &config,
                                 const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, "
            "returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof "
            "generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof "
            "commits to, or empty array if the proof is invalid\n");
    }

    CDataStream ssMB(ParseHexV(request.params[0], "proof"), SER_NETWORK,
                     PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    std::vector<uint256> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) !=
        merkleBlock.header.hashMerkleRoot) {
        return res;
    }

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) ||
        !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()])) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Block not found in chain");
    }

    for (const uint256 &hash : vMatch) {
        res.push_back(hash.GetHex());
    }

    return res;
}

static UniValue createrawtransaction(const Config &config,
                                     const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 2 ||
        request.params.size() > 3) {
        throw std::runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] "
            "{\"address\":amount,\"data\":\"hex\",...} ( locktime )\n"
            "\nCreate a transaction spending the given inputs and creating new "
            "outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"inputs\"                (array, required) A json array of "
            "json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction "
            "id\n"
            "         \"vout\":n,         (numeric, required) The output "
            "number\n"
            "         \"sequence\":n      (numeric, optional) The sequence "
            "number\n"
            "       } \n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"               (object, required) a json object "
            "with outputs\n"
            "    {\n"
            "      \"address\": x.xxx,    (numeric or string, required) The "
            "key is the bitcoin address, the numeric value (can be string) is "
            "the " +
            CURRENCY_UNIT +
            " amount\n"
            "      \"data\": \"hex\"      (string, required) The key is "
            "\"data\", the value is hex encoded data\n"
            "      ,...\n"
            "    }\n"
            "3. locktime                  (numeric, optional, default=0) Raw "
            "locktime. Non-0 value also locktime-activates inputs\n"
            "\nResult:\n"
            "\"transaction\"              (string) hex string of the "
            "transaction\n"

            "\nExamples:\n" +
            HelpExampleCli("createrawtransaction",
                           "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" "
                           "\"{\\\"address\\\":0.01}\"") +
            HelpExampleCli("createrawtransaction",
                           "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" "
                           "\"{\\\"data\\\":\\\"00010203\\\"}\"") +
            HelpExampleRpc("createrawtransaction",
                           "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", "
                           "\"{\\\"address\\\":0.01}\"") +
            HelpExampleRpc("createrawtransaction",
                           "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", "
                           "\"{\\\"data\\\":\\\"00010203\\\"}\""));
    }

    RPCTypeCheck(request.params,
                 {UniValue::VARR, UniValue::VOBJ, UniValue::VNUM}, true);
    if (request.params[0].isNull() || request.params[1].isNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Invalid parameter, arguments 1 and 2 must be non-null");
    }

    UniValue inputs = request.params[0].get_array();
    UniValue sendTo = request.params[1].get_obj();

    CMutableTransaction rawTx;

    if (request.params.size() > 2 && !request.params[2].isNull()) {
        int64_t nLockTime = request.params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, locktime out of range");
        }

        rawTx.nLockTime = nLockTime;
    }

    for (size_t idx = 0; idx < inputs.size(); idx++) {
        const UniValue &input = inputs[idx];
        const UniValue &o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue &vout_v = find_value(o, "vout");
        if (!vout_v.isNum()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, missing vout key");
        }

        int nOutput = vout_v.get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, vout must be positive");
        }

        uint32_t nSequence =
            (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1
                             : std::numeric_limits<uint32_t>::max());

        // Set the sequence number if passed in the parameters object.
        const UniValue &sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Invalid parameter, sequence number is out of range");
            }

            nSequence = uint32_t(seqNr64);
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);
        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    std::vector<std::string> addrList = sendTo.getKeys();
    for (const std::string &name_ : addrList) {
        if (name_ == "data") {
            std::vector<uint8_t> data =
                ParseHexV(sendTo[name_].getValStr(), "Data");

            CTxOut out(Amount(0), CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } else {
            CTxDestination destination =
                DecodeDestination(name_, config.GetChainParams());
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   std::string("Invalid Bitcoin address: ") +
                                       name_);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    std::string("Invalid parameter, duplicated address: ") +
                        name_);
            }

            CScript scriptPubKey = GetScriptForDestination(destination);
            Amount nAmount = AmountFromValue(sendTo[name_]);

            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        }
    }

    return EncodeHexTx(CTransaction(rawTx));
}

static UniValue decoderawtransaction(const Config &config,
                                     const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded "
            "transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"      (string, required) The transaction hex "
            "string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
            "  \"hash\" : \"id\",        (string) The transaction hash "
            "(differs from txid for witness transactions)\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " +
            CURRENCY_UNIT +
            "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg "
            "'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) "
            "bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("decoderawtransaction", "\"hexstring\"") +
            HelpExampleRpc("decoderawtransaction", "\"hexstring\""));
    }

    LOCK(cs_main);
    RPCTypeCheck(request.params, {UniValue::VSTR});

    CMutableTransaction mtx;

    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VOBJ);
    TxToUniv(CTransaction(std::move(mtx)), uint256(), result);

    return result;
}

static UniValue decodescript(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "decodescript \"hexstring\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hexstring\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) bitcoin address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) address of P2SH script wrapping "
            "this redeem script (not returned if the script is already a "
            "P2SH).\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("decodescript", "\"hexstring\"") +
            HelpExampleRpc("decodescript", "\"hexstring\""));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR});

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0) {
        std::vector<uint8_t> scriptData(
            ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid.
    }

    ScriptPubKeyToUniv(script, r, false);

    UniValue type;
    type = find_value(r, "type");

    if (type.isStr() && type.get_str() != "scripthash") {
        // P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
        // don't return the address for a P2SH of the P2SH.
        r.push_back(Pair("p2sh", EncodeDestination(CScriptID(script))));
    }

    return r;
}

/**
 * Pushes a JSON object for script verification or signing errors to vErrorsRet.
 */
static void TxInErrorToJSON(const CTxIn &txin, UniValue &vErrorsRet,
                            const std::string &strMessage) {
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.GetTxId().ToString()));
    entry.push_back(Pair("vout", uint64_t(txin.prevout.GetN())));
    entry.push_back(Pair("scriptSig",
                         HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", uint64_t(txin.nSequence)));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

static UniValue signrawtransaction(const Config &config,
                                   const JSONRPCRequest &request) {
#ifdef ENABLE_WALLET
    CWallet *const pwallet = GetWalletForJSONRPCRequest(request);
#endif

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 4) {
        throw std::runtime_error(
            "signrawtransaction \"hexstring\" ( "
            "[{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\","
            "\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype "
            ")\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of "
            "previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block "
            "chain.\n"
            "The third optional argument (may be null) is an array of "
            "base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the "
            "transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase(pwallet) +
            "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex "
            "string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous "
            "dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if "
            "none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The "
            "transaction id\n"
            "         \"vout\":n,                  (numeric, required) The "
            "output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script "
            "key\n"
            "         \"redeemScript\": \"hex\",   (string, required for P2SH "
            "or P2WSH) redeem script\n"
            "         \"amount\": value            (numeric, required) The "
            "amount spent\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privkeys\"     (string, optional) A json array of "
            "base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none "
            "provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The "
            "signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
            "       \"ALL|FORKID\"\n"
            "       \"NONE|FORKID\"\n"
            "       \"SINGLE|FORKID\"\n"
            "       \"ALL|FORKID|ANYONECANPAY\"\n"
            "       \"NONE|FORKID|ANYONECANPAY\"\n"
            "       \"SINGLE|FORKID|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw "
            "transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a "
            "complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script "
            "verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the "
            "referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the "
            "output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded "
            "signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence "
            "number\n"
            "      \"error\" : \"text\"           (string) Verification or "
            "signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("signrawtransaction", "\"myhex\"") +
            HelpExampleRpc("signrawtransaction", "\"myhex\""));
    }

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(
        request.params,
        {UniValue::VSTR, UniValue::VARR, UniValue::VARR, UniValue::VSTR}, true);

    std::vector<uint8_t> txData(ParseHexV(request.params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        } catch (const std::exception &) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");
    }

    // mergedTx will end up with all the signatures; it starts as a clone of the
    // rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        // Temporarily switch cache backend to db+mempool view.
        view.SetBackend(viewMempool);

        for (const CTxIn &txin : mergedTx.vin) {
            // Load entries from viewChain into view; can fail.
            view.AccessCoin(txin.prevout);
        }

        // Switch back to avoid locking mempool for too long.
        view.SetBackend(viewDummy);
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = request.params[2].get_array();
        for (size_t idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Invalid private key");
            }

            CKey key = vchSecret.GetKey();
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Private key outside allowed range");
            }

            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwallet) {
        EnsureWalletIsUnlocked(pwallet);
    }
#endif

    // Add previous txouts given in the RPC call:
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (size_t idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue &p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "expected object with "
                                   "{\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                            {
                                {"txid", UniValueType(UniValue::VSTR)},
                                {"vout", UniValueType(UniValue::VNUM)},
                                {"scriptPubKey", UniValueType(UniValue::VSTR)},
                                // "amount" is also required but check is done
                                // below due to UniValue::VNUM erroneously
                                // not accepting quoted numerics
                                // (which are valid JSON)
                            });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "vout must be positive");
            }

            COutPoint out(txid, nOut);
            std::vector<uint8_t> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                const Coin &coin = view.AccessCoin(out);
                if (!coin.IsSpent() &&
                    coin.GetTxOut().scriptPubKey != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin.GetTxOut().scriptPubKey) +
                          "\nvs:\n" + ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }

                CTxOut txout;
                txout.scriptPubKey = scriptPubKey;
                txout.nValue = Amount(0);
                if (prevOut.exists("amount")) {
                    txout.nValue =
                        AmountFromValue(find_value(prevOut, "amount"));
                } else {
                    // amount param is required in replay-protected txs.
                    // Note that we must check for its presence here rather
                    // than use RPCTypeCheckObj() above, since UniValue::VNUM
                    // parser incorrectly parses numerics with quotes, eg
                    // "3.12" as a string when JSON allows it to also parse
                    // as numeric. And we have to accept numerics with quotes
                    // because our own dogfood (our rpc results) always
                    // produces decimal numbers that are quoted
                    // eg getbalance returns "3.14152" rather than 3.14152
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing amount");
                }

                view.AddCoin(out, Coin(txout, 1, false), true);
            }

            // If redeemScript given and not using the local wallet (private
            // keys given), add redeemScript to the tempKeystore so it can be
            // signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheckObj(
                    prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    std::vector<uint8_t> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore &keystore =
        ((fGivenKeys || !pwallet) ? tempKeystore : *pwallet);
#else
    const CKeyStore &keystore = tempKeystore;
#endif

    SigHashType sigHashType = SigHashType().withForkId();
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        static std::map<std::string, int> mapSigHashValues = {
            {"ALL", SIGHASH_ALL},
            {"ALL|ANYONECANPAY", SIGHASH_ALL | SIGHASH_ANYONECANPAY},
            {"ALL|FORKID", SIGHASH_ALL | SIGHASH_FORKID},
            {"ALL|FORKID|ANYONECANPAY",
             SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY},
            {"NONE", SIGHASH_NONE},
            {"NONE|ANYONECANPAY", SIGHASH_NONE | SIGHASH_ANYONECANPAY},
            {"NONE|FORKID", SIGHASH_NONE | SIGHASH_FORKID},
            {"NONE|FORKID|ANYONECANPAY",
             SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY},
            {"SINGLE", SIGHASH_SINGLE},
            {"SINGLE|ANYONECANPAY", SIGHASH_SINGLE | SIGHASH_ANYONECANPAY},
            {"SINGLE|FORKID", SIGHASH_SINGLE | SIGHASH_FORKID},
            {"SINGLE|FORKID|ANYONECANPAY",
             SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY},
        };
        std::string strHashType = request.params[3].get_str();
        if (!mapSigHashValues.count(strHashType)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
        }

        sigHashType = SigHashType(mapSigHashValues[strHashType]);
        if (!sigHashType.hasForkId()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Signature must use SIGHASH_FORKID");
        }
    }

    // Script verification errors.
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the transaction to avoid
    // rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (size_t i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn &txin = mergedTx.vin[i];
        const Coin &coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }

        const CScript &prevPubKey = coin.GetTxOut().scriptPubKey;
        const Amount amount = coin.GetTxOut().nValue;

        SignatureData sigdata;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if ((sigHashType.getBaseType() != BaseSigHashType::SINGLE) ||
            (i < mergedTx.vout.size())) {
            ProduceSignature(MutableTransactionSignatureCreator(
                                 &keystore, &mergedTx, i, amount, sigHashType),
                             prevPubKey, sigdata);
        }

        // ... and merge in other signatures:
        for (const CMutableTransaction &txv : txVariants) {
            if (txv.vin.size() > i) {
                sigdata = CombineSignatures(
                    prevPubKey,
                    TransactionSignatureChecker(&txConst, i, amount), sigdata,
                    DataFromTransaction(txv, i));
            }
        }

        UpdateTransaction(mergedTx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(
                txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                TransactionSignatureChecker(&txConst, i, amount), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }

    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(CTransaction(mergedTx))));
    result.push_back(Pair("complete", fComplete));
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }

    return result;
}

static UniValue sendrawtransaction(const Config &config,
                                   const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node "
            "and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw "
            "transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high "
            "fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n" +
            HelpExampleCli("createrawtransaction",
                           "\"[{\\\"txid\\\" : "
                           "\\\"mytxid\\\",\\\"vout\\\":0}]\" "
                           "\"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n" +
            HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n" +
            HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("sendrawtransaction", "\"signedhex\""));
    }

    LOCK(cs_main);
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});

    // parse hex string from parameter
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    const uint256 &txid = tx->GetId();

    bool fLimitFree = false;
    Amount nMaxRawTxFee = maxTxFee;
    if (request.params.size() > 1 && request.params[1].get_bool()) {
        nMaxRawTxFee = Amount(0);
    }

    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t o = 0; !fHaveChain && o < tx->vout.size(); o++) {
        const Coin &existingCoin = view.AccessCoin(COutPoint(txid, o));
        fHaveChain = !existingCoin.IsSpent();
    }

    bool fHaveMempool = mempool.exists(txid);
    if (!fHaveMempool && !fHaveChain) {
        // Push to local node and sync with wallets.
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(config, mempool, state, std::move(tx),
                                fLimitFree, &fMissingInputs, false,
                                nMaxRawTxFee)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                                   strprintf("%i: %s", state.GetRejectCode(),
                                             state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }

                throw JSONRPCError(RPC_TRANSACTION_ERROR,
                                   state.GetRejectReason());
            }
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN,
                           "transaction already in block chain");
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    CInv inv(MSG_TX, txid);
    TxMempoolInfo txinfo { mempool.info(txid) };
    g_connman->EnqueueTransaction( {inv, txinfo} );

    LogPrint(BCLog::TXNSRC, "got txn rpc: %s txnsrc user=%s\n",
        inv.hash.ToString(), request.authUser.c_str());

    return txid.GetHex();
}

std::string getBlockHash(int height) {
    LOCK(cs_main);

    if (height < 0 || height > chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    CBlockIndex *pblockindex = chainActive[height];
    return pblockindex->GetBlockHash().GetHex();
}


int getBlockHeight(std::string strHash) {
    LOCK(cs_main);

    uint256 hash(uint256S(strHash));
    if (mapBlockIndex.count(hash) == 0) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    CBlockIndex *pblockindex = mapBlockIndex[hash];
    return pblockindex->nHeight;
}

bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address)
{
    CTxDestination dest;

    if (type == 2) {
        dest = CScriptID(hash);
    } else if (type == 1) {
        dest = CKeyID(hash);
    } else {
        return false;
    }

    address = EncodeBase58Addr(dest, Params());
    return true;
}

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, int> > &addresses)
{
    if (params[0].isStr()) {
        CBase58Data address;
        address.SetString(params[0].get_str());
        uint160 hashBytes;
        int type = 0;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address param");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else if (params[0].isObject()) {

        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
            CBase58Data address;
            address.SetString(it->get_str());
            uint160 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address. Code: 1");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address. Code: 2");
    }

    return true;
}

bool getAddressesFromFirstArray(const UniValue& addressValues, std::vector<std::pair<uint160, int> > &addresses)
{
    if (!addressValues.isArray()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
    }

    std::vector<UniValue> values = addressValues.getValues();

    for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
        CBase58Data address;
        address.SetString(it->get_str());
        uint160 hashBytes;
        int type = 0;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address. Code: 3");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    }
    return true;
}


bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                   std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b) {
    return a.second.time < b.second.time;
}

static UniValue getaddressutxos(const Config &config,
                                  const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 3  ||
        request.params.size() > 3 )
        throw std::runtime_error(
            "getaddressutxos\n"
            "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ],\n"
            "  \"chainInfo\"  (boolean) Include chain info with results\n"
            "}\n"
            "\nResult\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            );

    if (!request.params[0].isArray()) {
        throw JSONRPCError(
        RPC_TYPE_ERROR,
        "Invalid type provided. addresses parameter must be an array.");
    }

    int from = 0;
    if (!request.params[1].isNum()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. From parameter must be a int.");
    } else {
        from = request.params[1].get_int();
    }

    int to = 50;
    if (!request.params[2].isNum()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. To parameter must be a int.");
    } else {
        to = request.params[2].get_int();
    }

    bool includeChainInfo = true;
    /*if (request.params[0].isObject()) {
        UniValue chainInfo = find_value(request.params[0].get_obj(), "chainInfo");
        if (chainInfo.isBool()) {
            includeChainInfo = chainInfo.get_bool();
        }
    }*/

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromFirstArray(request.params[0], addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue utxos(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("utxos", utxos));

        LOCK(cs_main);
        result.push_back(Pair("hash", chainActive.Tip()->GetBlockHash().GetHex()));
        result.push_back(Pair("height", (int)chainActive.Height()));
        return result;
    } else {
        return utxos;
    }
}

static UniValue getaddressdeltas(const Config &config,
                                  const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1 || !request.params[0].isObject())
        throw std::runtime_error(
            "getaddressdeltas\n"
            "\nReturns all changes for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "  \"chainInfo\" (boolean) Include chain info in results, only applies if start and end specified\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"height\"  (number) The block height\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );


    UniValue startValue = find_value(request.params[0].get_obj(), "start");
    UniValue endValue = find_value(request.params[0].get_obj(), "end");

    UniValue chainInfo = find_value(request.params[0].get_obj(), "chainInfo");
    bool includeChainInfo = false;
    if (chainInfo.isBool()) {
        includeChainInfo = chainInfo.get_bool();
    }

    int start = 0;
    int end = 0;

    if (startValue.isNum() && endValue.isNum()) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (start <= 0 || end <= 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start and end is expected to be greater than zero");
        }
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, int64_t> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    UniValue deltas(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("satoshis", it->second));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("blockindex", (int)it->first.txindex));
        delta.push_back(Pair("height", it->first.blockHeight));
        delta.push_back(Pair("address", address));
        deltas.push_back(delta);
    }

    UniValue result(UniValue::VOBJ);

    if (includeChainInfo && start > 0 && end > 0) {
        LOCK(cs_main);

        if (start > chainActive.Height() || end > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start or end is outside chain range");
        }

        CBlockIndex* startIndex = chainActive[start];
        CBlockIndex* endIndex = chainActive[end];

        UniValue startInfo(UniValue::VOBJ);
        UniValue endInfo(UniValue::VOBJ);

        startInfo.push_back(Pair("hash", startIndex->GetBlockHash().GetHex()));
        startInfo.push_back(Pair("height", start));

        endInfo.push_back(Pair("hash", endIndex->GetBlockHash().GetHex()));
        endInfo.push_back(Pair("height", end));

        result.push_back(Pair("deltas", deltas));
        result.push_back(Pair("start", startInfo));
        result.push_back(Pair("end", endInfo));

        return result;
    } else {
        return deltas;
    }
}


static UniValue getaddressbalance(const Config &config,
                                  const JSONRPCRequest &request) {

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddressbalance\n"
            "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\"  (string) The current balance in satoshis\n"
            "  \"received\"  (string) The total number of satoshis received (including change)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, int64_t> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    int64_t balance = 0;
    int64_t received = 0;

    for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        if (it->second > 0) {
            received += it->second;
        }
        balance += it->second;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("balance", balance));
    result.push_back(Pair("received", received));

    return result;

}

static UniValue getaddresstxidsoffsets(const Config &config,
                                  const JSONRPCRequest &request) {

    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
            "getaddresstxidsoffsets\n"
            "\nReturns the txids for an address(es) with start and end offsets (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"from\" (number) The start index\n"
            "  \"to\" (number) The end index\n"
            "  \"afterHeight\": (number) Include tx's only after this height\n"
            "  \"afterBlockHash\": (string) Include tx's only after this blockHash. Takes precedence over afterHeight\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddresstxidsoffsets", "'[\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"], 0, 1'")
            + HelpExampleRpc("getaddresstxidsoffsets", "'[\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"], 0, 1'")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromFirstArray(request.params[0], addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    if (!request.params[0].isArray()) {
        throw JSONRPCError(
        RPC_TYPE_ERROR,
        "Invalid type provided. addresses parameter must be an array.");
    }

    int from = 0;
    if (!request.params[1].isNum()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. From parameter must be a int.");
    } else {
        from = request.params[1].get_int();
    }

    int to = 50;
    if (!request.params[2].isNum()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. To parameter must be a int.");
    } else {
        to = request.params[2].get_int();
    }

    std::string afterBlockHash;
    int afterHeight = 0;
    if (!request.params[3].isNum()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. AfterHeight parameter must be a int.");
    } else {
        afterHeight = request.params[3].get_int();

        if (afterHeight > 0) {
            afterBlockHash = getBlockHash(afterHeight);
        }
    }

    if (request.params.size() == 5) {
         if (!request.params[4].isStr()) {
            throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid type provided. AfterBlockHash parameter must be a string.");
        } else if (request.params[4].get_str().size()) {
            afterBlockHash = request.params[4].get_str();
            afterHeight = getBlockHeight(request.params[4].get_str());
        }
    }

    std::vector<std::pair<CAddressIndexKey, int64_t> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex, afterHeight + 1, 9999999)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >  addressMempoolResults;
    mempool.getAddressIndex(addresses, addressMempoolResults);

    // Store the tx's in the mempool for the addresses
    std::vector<std::pair<CAddressIndexKey, int64_t> > mempoolAddressIndex;
    for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::const_iterator it=addressMempoolResults.begin(); it!=addressMempoolResults.end(); it++) {
        CAddressIndexKey s;
        s.blockHeight = 999999999;
        s.hashBytes = it->first.addressBytes;
        s.txhash = it->first.txhash;
        s.type = it->first.type;
        s.txindex = true;
        s.spending = it->first.spending;
        mempoolAddressIndex.push_back(std::make_pair(s, it->second.amount));
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue txResults(UniValue::VARR);

    if (addresses.size() > 1) {
        int counter = 0;
        for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
            int height = it->first.blockHeight;
            std::string txid = it->first.txhash.GetHex();
            txids.insert(std::make_pair(height, txid));
        }

        // Add all the mempool tx's
        for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=mempoolAddressIndex.begin(); it!=mempoolAddressIndex.end(); it++) {
            int height = 999999999; // Set to very high because it is the mempool and we want them toshow up first
            std::string txid = it->first.txhash.GetHex();
            txids.insert(std::make_pair(height, txid));
        }

        for (std::set<std::pair<int, std::string> >::const_reverse_iterator it=txids.rbegin(); it!=txids.rend(); it++) {
            if (counter >= from && counter <= to) {
                UniValue txAndHeight(UniValue::VOBJ);
                txAndHeight.push_back(Pair("txid", it->second));
                if (it->first == 999999999) {
                    txAndHeight.push_back(Pair("h", 0));
                } else {
                    txAndHeight.push_back(Pair("h", it->first));
                }
                txResults.push_back(txAndHeight);
            }
            if (counter > to) {
                break;
            }
            counter++;
        }
    } else {
        int counter = 0;

        // Add all the mempool tx's
        for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=mempoolAddressIndex.begin(); it!=mempoolAddressIndex.end(); it++) {
            addressIndex.push_back(*it);
        }

        for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_reverse_iterator it=addressIndex.rbegin(); it!=addressIndex.rend(); it++) {
            int height = it->first.blockHeight;
            std::string txid = it->first.txhash.GetHex();
            if (txids.insert(std::make_pair(height, txid)).second) {
                if (counter >= from && counter <= to) {
                    UniValue txAndHeight(UniValue::VOBJ);
                    txAndHeight.push_back(Pair("txid", txid));
                    if (height == 999999999) {
                        txAndHeight.push_back(Pair("h", 0));
                    } else {
                        txAndHeight.push_back(Pair("h", height));
                    }
                    txResults.push_back(txAndHeight);
                }
                if (counter > to) {
                    break;
                }
                counter++;
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    UniValue totalItems(UniValue::VNUM);

    result.push_back(Pair("from", from));
    result.push_back(Pair("to", to));


    if (afterBlockHash != "") {
        result.push_back(Pair("afterBlockHash", afterBlockHash));
        result.push_back(Pair("afterHeight", afterHeight));
    } else {
        result.push_back(Pair("afterHeight", afterHeight));
    }
    result.push_back(Pair("totalItems", (int) txids.size()));
    result.push_back(Pair("txs", txResults));
    return result;
}

static UniValue getaddresstxids(const Config &config,
                                  const JSONRPCRequest &request) {

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddresstxids\n"
            "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (request.params[0].isObject()) {
        UniValue startValue = find_value(request.params[0].get_obj(), "start");
        UniValue endValue = find_value(request.params[0].get_obj(), "end");
        if (startValue.isNum() && endValue.isNum()) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    std::vector<std::pair<CAddressIndexKey, int64_t> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, int64_t> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;

}

// clang-format off
static const CRPCCommand commands[] = {
    //  category            name                      actor (function)        okSafeMode
    //  ------------------- ------------------------  ----------------------  ----------
    { "rawtransactions",    "getrawtransaction",      getrawtransaction,      true,  {"txid","verbose"} },
    { "rawtransactions",    "createrawtransaction",   createrawtransaction,   true,  {"inputs","outputs","locktime"} },
    { "rawtransactions",    "decoderawtransaction",   decoderawtransaction,   true,  {"hexstring"} },
    { "rawtransactions",    "decodescript",           decodescript,           true,  {"hexstring"} },
    { "rawtransactions",    "sendrawtransaction",     sendrawtransaction,     false, {"hexstring","allowhighfees"} },
    { "rawtransactions",    "signrawtransaction",     signrawtransaction,     false, {"hexstring","prevtxs","privkeys","sighashtype"} }, /* uses wallet if enabled */
    { "rawtransactions",    "getrawtransactions",     getrawtransactions,     true,  {"txids", "includeAsm", "includeHex"} },
    { "blockchain",         "gettxoutproof",          gettxoutproof,          true,  {"txids", "blockhash"} },
    { "blockchain",         "verifytxoutproof",       verifytxoutproof,       true,  {"proof"} },
    { "address",            "getaddresstxids",        getaddresstxids,        true,  {"addresses", "start", "end"} },
    { "address",            "getaddresstxidsoffsets", getaddresstxidsoffsets, true,  {"addresses", "from", "to" } },
    { "address",            "getaddressbalance",      getaddressbalance,      true,  {"addresses"} },
    { "address",            "getaddressutxos",        getaddressutxos,        true,  {"addresses", "chaininfo"} }
};
// clang-format on

void RegisterRawTransactionRPCCommands(CRPCTable &t) {
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}

