#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

class MerkleTree
{
    protected:
        std::vector<uint64_t*> mempool; // each index of pointer has length of 8
    
    public:
        uint64_t* MerkleRoot()
        {
            IntTypes int_type = IntTypes();
            uint64_t singleHash[8];
            memcpy(singleHash,sha512("sender: N/A-receiver: N/A-amount: N/A"), 64);
            mempool.push_back(singleHash);
            
            __uint128_t len = mempool.size();
            for(int c=0;c<8;c++) {
                uint64_t x = mempool.at(0)[c];
                std::cout << std::hex << x << " ";
            }
            bool odd = true;
            
            // calculate MerkleRoot
            for(__uint128_t c=0;c<len;c++) {
                for(int i=0;i<8;i++) {
                    if (len%2 == odd) {
                        //  = mempool[c][i];
                    } 
                    else if(len%2 != odd) {
                        
                    }
                }
            }
            return nullptr;
        }
};

class Node : public MerkleTree
{
    
};
