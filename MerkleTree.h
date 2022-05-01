/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: Apr 9, 2022
*
*/

#ifndef MERKLETREE_H_
#define MERKLETREE_H_

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
                    for(double c=0;c<len/2;c++) {
                            nodes.push_back(hash.sha512_ptr(Plevel[(uint64_t)(c*2)],
                                                            Plevel[(uint64_t)(c*2+1)]));
                    }
                    /* nodes are single a layer of the MerkleTree */
                    return nodes;
                }
            public:
                std::shared_ptr<uint64_t> append_levels(std::vector<std::shared_ptr
                                                        <uint64_t>> mempool, 
                                                        uint64_t len, std::
                                                        shared_ptr<uint64_t>
                                                        merkle_root)
                {
                    uint64_t currlen = len;
                    std::vector<std::shared_ptr<uint64_t>> level = mempool;
                    while(currlen != 1) {
                        level = append_level(level, currlen);
                        currlen/=2;
                    } if(level.size() == 1) {
                        merkle_root = std::move(std::shared_ptr<uint64_t>
                                                (level[0]));
                    }
                    return merkle_root;
                }
        };
        
        inline std::shared_ptr<uint64_t> merkleRoot(std::vector<std::shared_ptr
                                                    <uint64_t>> Mempool)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            Node node = Node();
            
            // declare merkle root
            alignas(uint64_t) std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            
            // to avoid 0 hashes to be invalid transactions in Mempool
            std::vector<std::shared_ptr<uint64_t>> mempool = Mempool;
            
            uint64_t len = mempool.size(); // amount of transactions in the block
            uint64_t validlen = 2;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                std::shared_ptr<uint64_t> oddZfill(new uint64_t[8]);
                
                // TODO: convert "00000000" to memset("", "0", validlen); in future version
                oddZfill = sha512("00000000"); 
                mempool.push_back(oddZfill);
                len++; // update len
            }
            
            // calculate amount of layers
            while(validlen != 0) {
                validlen/=2;
                /* validlen gets set to zero so don't use it after this loop */
            }
            // calculate Merkle Root
            merkle_root = node.append_levels(mempool, len, merkle_root);
            return merkle_root;
        }
}; // namespace MerkleTree

#endif /* MERKLETREE_H_ */
