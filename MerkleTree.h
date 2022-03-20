#include <stdint.h>
#include <vector>
#include <string>
#include <memory>
#include "sha512.h"

namespace MerkleTree
{
        std::vector<std::shared_ptr<uint64_t>> merkleRoots;
        
        inline uint64_t length(std::vector<std::shared_ptr<uint64_t>> mempool)
        {
            return mempool.size();
        }
        
        class Node
        {
            private:
                std::vector<std::shared_ptr<uint64_t>> append_level(std::vector
                                                                    <std::shared_ptr
                                                                    <uint64_t>>
                                                                    Plevel,
                                                                    uint64_t len)
                {
                    SHA512 hash = SHA512();
                    std::vector<std::shared_ptr<uint64_t>> nodes;
                    for(double r=0;r<len/2;r++) {
                            nodes.push_back(hash.sha512_ptr(Plevel[(uint64_t)(r*2)],
                                                            Plevel[(uint64_t)(r*2+1)]));
                    }
                    /* nodes are single a layer of the MerkleTree */
                    /* update Plevel to level in another function until len = 1 */
                    return nodes;
                }
            public:
                void append_levels(std::vector<std::shared_ptr<uint64_t>> mempool, uint64_t len,
                                   std::shared_ptr<uint64_t> merkle_root)
                {
                    uint64_t currlen = len;
                    std::vector<std::shared_ptr<uint64_t>> level = mempool;
                    while(currlen != 1) {
                        level = append_level(level, currlen);
                        currlen/=2;
                    } if(level.size() == 1) {
                        merkle_root = std::move(std::shared_ptr<uint64_t>
                                                (level[0]));
                        std::cout << "\ncondition met\n"; /* test a few times */
                    } else {
                        std::cout << "error, condition not met";
                        exit(EXIT_FAILURE);
                    }
                }
        };
        
        inline void merkleRoot(std::vector<std::shared_ptr<uint64_t>> Mempool,
                               std::shared_ptr<uint64_t> merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            Node node = Node();
            
            // to avoid 0 hashes to be invalid transactions in Mempool
            std::vector<std::shared_ptr<uint64_t>> mempool = Mempool;
            
            uint64_t len = mempool.size(); // amount of transactions in the block
            uint64_t validlen = 2;
            uint32_t amountofLayers = 0;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                std::shared_ptr<uint64_t> oddZfill(new uint64_t[8]);
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++; // update len
            }
            
            // calculate amount of layers
            while(validlen != 0) {
                validlen/=2;
                amountofLayers++;
                /* validlen gets set to zero so don't use it after this loop */
            }
            // calculate MerkleRoot
            node.append_levels(mempool, len, merkle_root);
            
            // store merkle_root in vector merkleRoots
            merkleRoots.push_back(merkle_root);
        }
}; // namespace MerkleTree
