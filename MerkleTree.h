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
            SHA512 hash = SHA512();
            uint64_t len = mempool.size();
            bool odd = true;
            uint64_t* merkle_root;
            /* TEST START sha512_ptr */
            hash.sha512_ptr(mempool[0], mempool[0]);
            /* TEST END sha512_ptr*/
            
            if(len == 1) { // if len 1, use the same hash twice to get merkle_root
                std::string SINGLE_HASH_MEMLEN1="";
                for(int c=0;c<8;c++) {
                    SINGLE_HASH_MEMLEN1 += std::to_string(mempool[0][c]);
                }
                // use hash.sha512_ptr to avoid string
                merkle_root = sha512(SINGLE_HASH_MEMLEN1 + SINGLE_HASH_MEMLEN1);
            } else {
                // calculate MerkleRoot
                for(uint64_t c=0;c<len;c++) {
                    for(int i=0;i<8;i++) {
                        if (len%2 == odd) {
                            
                        }
                        else if(len%2 != odd) {
                            
                        }
                    }
                }
            }
            return merkle_root;
        }
};

class Node : public MerkleTree
{
    
};
