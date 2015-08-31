// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "arith_uint256.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "crypto/sha256.h"
#include "eccryptoverify.h"
#include "pubkey.h"
#include "random.h"
#include "util.h"

#include <secp256k1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "ecwrapper.h"

#define BIP39_BITS_PER_WORD 11
#define BIP39_PBKDF2_ROUNDS 2048
#define BIP39_WORDS (1 << BIP39_BITS_PER_WORD)

static secp256k1_context_t* secp256k1_context = NULL;

bool CKey::Check(const unsigned char *vch) {
    return eccrypto::Check(vch);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    RandAddSeedPerfmon();
    do {
        GetRandBytes(vch, sizeof(vch));
    } while (!Check(vch));
    fValid = true;
    fCompressed = fCompressedIn;
}

bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn) {
    if (!secp256k1_ec_privkey_import(secp256k1_context, (unsigned char*)begin(), &privkey[0], privkey.size()))
        return false;
    fCompressed = fCompressedIn;
    fValid = true;
    return true;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CPrivKey privkey;
    int privkeylen, ret;
    privkey.resize(279);
    privkeylen = 279;
    ret = secp256k1_ec_privkey_export(secp256k1_context, begin(), (unsigned char*)&privkey[0], &privkeylen, fCompressed);
    assert(ret);
    privkey.resize(privkeylen);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    CPubKey result;
    int clen = 65;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context, (unsigned char*)result.begin(), &clen, begin(), fCompressed);
    assert((int)result.size() == clen);
    assert(ret);
    assert(result.IsValid());
    return result;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    if (!fValid)
        return false;
    vchSig.resize(72);
    int nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    int ret = secp256k1_ecdsa_sign(secp256k1_context, hash.begin(), (unsigned char*)&vchSig[0], &nSigLen, begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : NULL);
    assert(ret);
    vchSig.resize(nSigLen);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    int ret = secp256k1_ecdsa_sign_compact(secp256k1_context, hash.begin(), &vchSig[1], begin(), secp256k1_nonce_function_rfc6979, NULL, &rec);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (!secp256k1_ec_privkey_import(secp256k1_context, (unsigned char*)begin(), &privkey[0], privkey.size()))
        return false;
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert(IsCompressed());
    unsigned char out[64];
    LockObject(out);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, out);
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), out);
    }
    memcpy(ccChild.begin(), out+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context, (unsigned char*)keyChild.begin(), out);
    UnlockObject(out);
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return key.Derive(out.key, out.chaincode, nChild, chaincode);
}

void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    unsigned char out[64];
    LockObject(out);
    CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(out);
    key.Set(&out[0], &out[32], true);
    memcpy(chaincode.begin(), &out[32], 32);
    UnlockObject(out);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+74, true);
}

bool ECC_InitSanityCheck() {
    if (!CECKey::SanityCheck()) {
        return false;
    }
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}


void ECC_Start() {
    assert(secp256k1_context == NULL);

    secp256k1_context_t *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];
        LockObject(seed);
        GetRandBytes(seed, 32);
        bool ret = secp256k1_context_randomize(ctx, seed);
        assert(ret);
        UnlockObject(seed);
    }

    secp256k1_context = ctx;
}

void ECC_Stop() {
    secp256k1_context_t *ctx = secp256k1_context;
    secp256k1_context = NULL;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}



BIP39Mnemonic::BIP39Mnemonic(const std::string *setWords) {
    this -> words = setWords;
    // TODO: Should we keep our own copy of the words?
    for (int wordIdx = 0; wordIdx < BIP39_WORDS; wordIdx++) {
        wordMap[*(setWords + wordIdx)] = wordIdx;
    }
}

bool BIP39Mnemonic::GetEntropy(std::vector<unsigned char> &entropy) {
    size_t concatLenBits = 0;
    std::vector<unsigned char> concatBits;

    // Convert each word into 11 bits of entropy and store each bit in an array
    std::istringstream wordStream(this -> mnemonic);
    std::string word;
    while (std::getline(wordStream, word, ' ')) {
        try {
            const uint16_t val = wordMap.at(word);

            for (uint8_t bitIdx = 0; bitIdx < BIP39_BITS_PER_WORD; bitIdx++) {
                const uint16_t mask = 0x01 << (BIP39_BITS_PER_WORD - 1 - bitIdx);
                if (val & mask) {
                    concatBits.push_back(1);
                } else {
                    concatBits.push_back(0);
                }
            }
            concatLenBits += BIP39_BITS_PER_WORD;
        } catch(std::out_of_range e) {
            return error("Unmatched word \"%s\".", word.c_str());
        }
    }

    const size_t checksumLengthBits = concatLenBits / (BIP39_BITS_PER_WORD * 3);
    const size_t entropyLengthBits = concatLenBits - checksumLengthBits;

    // Repack the bits into the entropy array, stopping before the checksum bits
    entropy.clear();
    uint8_t currentByte = 0;
    uint8_t bitsFilled = 0;
    CSHA256 hasher;
    std::vector<unsigned char>::const_iterator it = concatBits.begin();

    for (uint16_t entropyIdx = 0; entropyIdx < entropyLengthBits; entropyIdx++, it++) {
        currentByte |= *it << (7 - bitsFilled);
        if (bitsFilled == 7) {
            entropy.push_back(currentByte);
            hasher.Write(&currentByte, 1);
            currentByte = 0;
            bitsFilled = 0;
        } else {
            bitsFilled++;
        }
    }

    unsigned char hashBytes[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hashBytes);

    for (uint16_t checkIdx = 0; checkIdx < checksumLengthBits; checkIdx++, it++) {
        const uint8_t byteIdx = checkIdx / 8;
        const uint8_t bitIdx = 7 - (checkIdx % 8);
        const uint8_t mask = 0x01 << bitIdx; // Mask for the bit we want to extract
        const uint8_t actualBit = (hashBytes[byteIdx] & mask) >> bitIdx;

        if (*it != actualBit) {
            return error("Failed checksum at bit %d.", checkIdx);
        }
    }

    return true;
}

const std::string &BIP39Mnemonic::GetMnemonic() {
    return this -> mnemonic;
}

bool BIP39Mnemonic::GetSeed(const std::string &passphrase, CExtKey &key) {
    unsigned char out[BIP39_KEY_LENGTH];
    GetSeed(passphrase, out);
    key.SetMaster(out, BIP39_KEY_LENGTH);
    return true;
}

bool BIP39Mnemonic::GetSeed(const std::string &passphrase, unsigned char *seed) {
    const char *mnemonicStr = "mnemonic";
    const size_t saltSize = strlen(mnemonicStr) + passphrase.size();
    unsigned char salt[saltSize + 1];

    // Salt is a fixed header string followed by the supplied passphrase
    memcpy(salt, mnemonicStr, strlen(mnemonicStr));
    memcpy(salt + strlen(mnemonicStr), passphrase.c_str(), passphrase.size());
    salt[saltSize] = 0; // Null terminate

    if (PKCS5_PBKDF2_HMAC(this -> mnemonic.c_str(), -1,
        salt, saltSize,
        BIP39_PBKDF2_ROUNDS, EVP_sha512(),
        BIP39_KEY_LENGTH, seed) != 0) {
        return error("PBKDF2 key derivation failed: %d", ERR_get_error());
    }
    return true;
}

bool BIP39Mnemonic::SetEntropy(const std::vector<unsigned char> &setEntropy) {
    // Entropy must be a multiple of 4 bytes so that it can be packed correctly
    if (setEntropy.size() % 4 != 0) {
        return error("Data length in bits should be divisible by 32, but it is not (%d bytes = %d bits).",
            setEntropy.size(), setEntropy.size() * 8);
    }

    const size_t entropyLengthBits = setEntropy.size() * 8;
    const size_t checksumLengthBits = entropyLengthBits / 32;
    std::vector<unsigned char> concatBits;

    CSHA256 hasher;

    // Unpack the bytes into individual bits
    for (std::vector<unsigned char>::const_iterator it = setEntropy.begin(); it != setEntropy.end(); it++) {
        unsigned char val = *it;
        hasher.Write(&val, 1);

        for (uint8_t bitIdx = 0; bitIdx < 8; bitIdx++) {
            uint8_t mask = 0x01 << (7 - bitIdx);
            if (val & mask) {
                concatBits.push_back(1);
            } else {
                concatBits.push_back(0);
            }
        }
    }

    // Calculate checksum of the bytes
    unsigned char hashBytes[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hashBytes);

    // Append checksum bits to the end of the entropy bits

    for (uint16_t checkIdx = 0; checkIdx < checksumLengthBits; checkIdx++) {
        const uint8_t byteIdx = checkIdx / 8;
        const uint8_t bitIdx = 7 - (checkIdx % 8);
        const uint8_t mask = 0x01 << bitIdx; // Mask for the bit we want to extract
        const uint8_t actualBit = (hashBytes[byteIdx] & mask) >> bitIdx;

        concatBits.push_back(actualBit);
    }

    this -> mnemonic.erase();
    uint8_t ordinality = BIP39_BITS_PER_WORD - 1;
    uint16_t val = 0;
    for (std::vector<unsigned char>::const_iterator it = concatBits.begin(); it != concatBits.end(); it++) {
        if (*it) {
            val |= (0x01 << ordinality);
        }

        if (ordinality == 0) {
            if (!this -> mnemonic.empty()) {
                this -> mnemonic += " ";
            }
            this -> mnemonic += words[val];
            val = 0;
            ordinality = BIP39_BITS_PER_WORD - 1;
        } else {
            ordinality--;
        }
    }

    return true;
}

bool BIP39Mnemonic::SetMnemonic(const std::string &phrase) {
    this -> mnemonic = phrase;

    // Use GetEntropy() to run validity checks. Note that in theory
    // we have to accept arbitrary word sequences in order to comply with the
    // specification, so we don't reject, we just let the caller know.
    std::vector<unsigned char> entropy;
    return GetEntropy(entropy);
}
