// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLET_ISMINE_H
#define BITCOIN_WALLET_WALLET_ISMINE_H

#include "script/standard.h"

#include <stdint.h>

class CKeyStore;
class CScript;

/** IsMine() return codes */
enum isminetype
{
    ISMINE_NO = 0,
    //! Indicates that we dont know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_UNSOLVABLE = 1,
    //! Indicates that we know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_SOLVABLE = 2,
    ISMINE_WATCH_ONLY = ISMINE_WATCH_SOLVABLE | ISMINE_WATCH_UNSOLVABLE,
    ISMINE_SPENDABLE = 4,
    ISMINE_ALL = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE
};
/** used for bitflags of isminetype */
typedef uint8_t isminefilter;

/** Determine whether the given script pubkey belongs to the keystore.
 * Optionally will return the solved key ID, where available, if pKeyID is not NULL.
 */
isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, CKeyID *pKeyID = NULL);
/** Determine whether the given TX destination belongs to the keystore.
 * Optionally will return the solved key ID, where available, if pKeyID is not NULL.
 */
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest, CKeyID *pKeyID = NULL);

#endif // BITCOIN_WALLET_WALLET_ISMINE_H
