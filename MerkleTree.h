#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

class MerkleTree
{
    public:
        uint64_t* MerkleRoot(std::vector<uint64_t*> mempool)
        {
            IntTypes int_type = IntTypes();
            __uint128_t len = mempool.size();
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
