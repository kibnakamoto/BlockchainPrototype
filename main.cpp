/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: N/A
*
* This implementation only works for C++ version c++17 or above. 
* C++ 14 also works but gives warning
* 
*/

#include <iostream>
#include <string>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"

struct SingleMempoolHash64 {
    
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    MerkleTree merkle_tree = MerkleTree();
    uint64_t SingleMempoolHash64[8];
    memcpy(SingleMempoolHash64, sha512("sender: N/A-receiver: N/A-amount: N/A"),
           sizeof(uint64_t)<<3);
    for(uint64_t c : SingleMempoolHash64) {
        std::cout << std::hex << c << " ";
    }
    std::vector<uint64_t*> mempool;
    uint64_t singleHash[8];
    
    memcpy(singleHash,sha512("sender: N/A-receiver: N/A-amount: N/A"), 64);
    mempool.push_back(singleHash);
    merkle_tree.MerkleRoot(mempool);
    
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
