#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

namespace MerkleTree
{
        std::vector<uint64_t*> merkleRoots;
        
        inline uint64_t length(std::vector<uint64_t*> mempool)
        {
            return mempool.size();
        }
        
        inline std::vector<uint64_t*> addleaf(uint64_t* concHash)
        {
            std::vector<uint64_t*> leaf;
            leaf.push_back(concHash);
            return leaf;
        }
        
        class Node
        {
            public:
                
        }
        
        inline void MerkleRoot(std::vector<uint64_t*> Mempool, uint64_t* merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            
            // to avoid 0 hashes to be invalid transactions in Mempool
            std::vector<uint64_t*> mempool = Mempool;
            uint64_t len = mempool.size(); // amount of transactions in the block
            __uint128_t validlen = 2;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++; // update len
            }
            
            // calculate MerkleRoot
            uint64_t currlen = len;
            std::vector<uint64_t*> leaves;
            while(currlen != 1) {
                // update current length of leaves until MerkleRoot
                currlen /= 2;
                
                // calculate leaf
                for(int i=0;i<currlen;i++) {
                    leaves.push_back(hash.sha512_ptr(mempool[i], mempool[i+1]));
                }
            }
            merkleRoots.push_back(merkle_root);
        }
}; // namespace MerkleTree
