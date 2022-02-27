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
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"

struct SingleMempoolHash {
    uint64_t* sender;
    uint64_t* receiver;
    uint32_t amount;
    
    // A single hashed transaction data
    uint64_t* transactionHash()
    {
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender[c]) + " ";
        }
        std::cout << transactionData; // wrong, TODO: fix
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver[c]) + " ";
        }
        transactionData += ", amount: " + std::to_string(amount);
        
        return sha512(transactionData);
    }
};

uint64_t* GenerateNewWalletAddress(uint64_t* private_key, uint64_t* public_key)
{
    return nullptr;
}

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    MerkleTree merkle_tree = MerkleTree();
    uint64_t SingleMempoolHash64[8];
    uint64_t merkle_root[8]; // declare Merkle Root
    
    /* Sample Hash Value */
    memcpy(SingleMempoolHash64, sha512("sender: N/A-receiver: N/A-amount: N/A"),
           sizeof(uint64_t)<<3);
    for(uint64_t c : SingleMempoolHash64) {
        std::cout << std::hex << c << " ";
    }
    std::vector<uint64_t*> mempool; // declare mempool
    
    struct SingleMempoolHash transaction{sha512("sender"), sha512("receiver"),
                                         50000};
    mempool.push_back(transaction.transactionHash());
    merkle_tree.MerkleRoot(mempool, merkle_root);
    
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
