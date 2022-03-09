
#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"
class MerkleTree
{
    public:
        uint64_t* MerkleRoot(std::vector<uint64_t*> mempool, uint64_t* merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            uint64_t len = mempool.size();
            bool odd = true;
            // calculate MerkleRoot
            for(uint64_t c=0;c<len;c++) {
                for(int i=0;i<8;i++) {
                    if (len%2 == odd) {
                        
                    }
                    else if(len%2 != odd) {
                        
                    }
                }
            }
            return merkle_root;
        }
};
