// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <sstream>
#include <string>
#include <vector>

#include "data/bip39_vectors.json.h"

#include "bip39.h"
#include "key.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include "univalue/univalue.h"

extern UniValue read_json(const std::string& jsondata);

BOOST_FIXTURE_TEST_SUITE(bip39_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip39_words_to_entropy) {
    UniValue tests = read_json(std::string(json_tests::bip39_vectors, json_tests::bip39_vectors + sizeof(json_tests::bip39_vectors)));
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        BIP39Mnemonic mnemonic(bip39_words_english);
        UniValue test = tests[idx];
        std::vector<unsigned char> expectedEntropy = ParseHex(test[0].get_str());
        std::string phrase = test[1].get_str();
        std::vector<unsigned char> expectedSeed = ParseHex(test[2].get_str());

        std::vector<unsigned char> actualEntropy;
        BOOST_REQUIRE(mnemonic.SetMnemonic(phrase));
        mnemonic.GetEntropy(actualEntropy);

        BOOST_CHECK_EQUAL(actualEntropy.size(), expectedEntropy.size());
        for (uint8_t entropyIdx = 0; entropyIdx < expectedEntropy.size(); entropyIdx++) {
            BOOST_CHECK_EQUAL(actualEntropy[entropyIdx], expectedEntropy[entropyIdx]);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip39_entropy_to_words) {
    UniValue tests = read_json(std::string(json_tests::bip39_vectors, json_tests::bip39_vectors + sizeof(json_tests::bip39_vectors)));
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        BIP39Mnemonic mnemonic(bip39_words_english);
        UniValue test = tests[idx];
        std::vector<unsigned char> entropy = ParseHex(test[0].get_str());
        std::string expectedPhrase = test[1].get_str();
        std::vector<unsigned char> expectedSeed = ParseHex(test[2].get_str());

        mnemonic.SetEntropy(entropy);
        const std::string actualPhrase = mnemonic.GetMnemonic();

        BOOST_CHECK_EQUAL(actualPhrase, expectedPhrase);
    }
}

BOOST_AUTO_TEST_CASE(bip39_entropy_to_seed) {
    UniValue tests = read_json(std::string(json_tests::bip39_vectors, json_tests::bip39_vectors + sizeof(json_tests::bip39_vectors)));
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        BIP39Mnemonic mnemonic(bip39_words_english);
        UniValue test = tests[idx];
        std::vector<unsigned char> entropy = ParseHex(test[0].get_str());
        std::vector<unsigned char> expectedSeed = ParseHex(test[2].get_str());

        mnemonic.SetEntropy(entropy);

        unsigned char actualSeed[BIP39_KEY_LENGTH];
        mnemonic.GetSeed(std::string("TREZOR"), actualSeed);
        for (uint8_t seedIdx = 0; seedIdx < expectedSeed.size(); seedIdx++) {
            BOOST_CHECK_EQUAL(actualSeed[seedIdx], expectedSeed[seedIdx]);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip39_validate_words) {
    // Intentionally break the second to last word so that the checksum is invalid
    std::string phrase = "legal winner thank year wave sausage worth useful legal winner winner yellow";
    BIP39Mnemonic mnemonic(bip39_words_english);

    BOOST_CHECK(!mnemonic.SetMnemonic(phrase));
}

// TODO: Need test cases past 24 words to confirm byte boundaries are handled correctly in the checksum code

BOOST_AUTO_TEST_SUITE_END()
