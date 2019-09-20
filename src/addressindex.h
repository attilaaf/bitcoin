// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRESSINDEX_H
#define BITCOIN_ADDRESSINDEX_H

#include "uint256.h"
#include "amount.h"
#include "utilstrencodings.h"

struct CMempoolAddressPotentialSpendsDelta
{
    uint256 txhash;
    unsigned int outputIndex;

    CMempoolAddressPotentialSpendsDelta(uint256 hash, unsigned int out) {
        txhash = hash;
        outputIndex = out;
    }

    CMempoolAddressPotentialSpendsDelta() {
        txhash.SetNull();
        outputIndex = 0;
    }
};

struct CMempoolAddressDelta
{
    int64_t time;
    int64_t amount;
    uint256 prevhash;
    unsigned int prevout;
    CScript scriptPubKey;

    CMempoolAddressDelta(int64_t t, int64_t a, uint256 hash, unsigned int out, CScript scriptPubKeyValue) {
        time = t;
        amount = a;
        prevhash = hash;
        prevout = out;
        scriptPubKey = scriptPubKeyValue;
    }

    CMempoolAddressDelta(int64_t t, int64_t a) {
        time = t;
        amount = a;
        prevhash.SetNull();
        prevout = 0;
        scriptPubKey = 0;
    }

    CMempoolAddressDelta(int64_t t, int64_t a, CScript scriptPubKeyValue) {
        time = t;
        amount = a;
        prevhash.SetNull();
        prevout = 0;
        scriptPubKey = scriptPubKeyValue;
    }
};

struct CMempoolAddressDeltaKey
{
    int type;
    uint160 addressBytes;
    uint256 txhash;
    unsigned int index;
    int spending;

    CMempoolAddressDeltaKey(int addressType, uint160 addressHash, uint256 hash, unsigned int i, int s) {
        type = addressType;
        addressBytes = addressHash;
        txhash = hash;
        index = i;
        spending = s;
    }

    CMempoolAddressDeltaKey(int addressType, uint160 addressHash) {
        type = addressType;
        addressBytes = addressHash;
        txhash.SetNull();
        index = 0;
        spending = 0;
    }
};

struct CMempoolAddressDeltaKeyCompare
{
    bool operator()(const CMempoolAddressDeltaKey& a, const CMempoolAddressDeltaKey& b) const {
        if (a.type == b.type) {
            if (a.addressBytes == b.addressBytes) {
                if (a.txhash == b.txhash) {
                    if (a.index == b.index) {
                        return a.spending < b.spending;
                    } else {
                        return a.index < b.index;
                    }
                } else {
                    return a.txhash < b.txhash;
                }
            } else {
                return a.addressBytes < b.addressBytes;
            }
        } else {
            return a.type < b.type;
        }
    }
};

struct CMempoolAddressPotentialSpendsKeyCompare
{
    bool operator()(const std::pair<uint256, int>& a, const std::pair<uint256, int>& b) const {
        if (a.first == b.first) {
            return a.second < b.second;
        } else {
            return a.first < b.first;
        }
    }
};

#endif // BITCOIN_ADDRESSINDEX_H
