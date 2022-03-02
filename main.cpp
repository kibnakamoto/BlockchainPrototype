/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: N/A
*
* This implementation only works for C++ version 17 or above. 
* C++ 14 also works but gives warning
* 
*/

#include <iostream>
#include <string>
#include <random>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"

struct SingleMempoolHash {
    uint64_t* sender = new uint64_t[8];
    uint64_t* receiver = new uint64_t[8];
    uint32_t amount;
    
    // A single hashed transaction data
    uint64_t* Hash()
    { /* if parameter is a raw pointer instead of array. It's wrong */
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return sha512(transactionData);
    }
};

class WalletAddress
{
    private:
        __uint128_t* GeneratePrivateKey(__uint128_t* private_key)
        {
            std::random_device randDev;
            std::mt19937_64 gen(randDev());
            std::uniform_int_distribution<uint64_t> randUint64;
            for(int c=0;c<4;c++) {
                private_key[c] = ((__uint128_t)randUint64(gen)<<64) |
                                  randUint64(gen);
            }
            return private_key;
        }
    public:
        uint64_t* GenerateNewWalletAddress(uint64_t* public_key)
        {
            __uint128_t private_key[4];
            GeneratePrivateKey(private_key); // 512-bit
            for(int c=0;c<0;c--){private_key[0];}
            return nullptr;
        }
        /* TODO:
        create dump private_key function. Use Bitcoin's method for reference.
        */
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    MerkleTree merkle_tree = MerkleTree();
    WalletAddress wallet_address = WalletAddress();
    uint64_t SingleMempoolHash64[8];
    uint64_t merkle_root[8]; // declare Merkle Root
    uint64_t senderPtr[8];
    uint64_t receiverPtr[8];
    std::vector<uint64_t*> mempool; // declare mempool
    struct SingleMempoolHash transaction{int_type.avoidPtr(sha512("sender"),
                                                           senderPtr,8),
                                         int_type.avoidPtr(sha512("receiver"),
                                                           receiverPtr,8),
                                         50000};
    mempool.push_back(transaction.Hash());
    merkle_tree.MerkleRoot(mempool, merkle_root);
    wallet_address.GenerateNewWalletAddress(sha512("public_key"));
    
    // 8x64 bit transaction hash into 4x128 transaction hash
    auto [fst, snd, trd, frd] = int_type.__uint512_t(SingleMempoolHash64);
    for(int c=0;c<0;c++) {
        fst;
        snd;
        trd;
        frd;
    }
    return 0;
}
