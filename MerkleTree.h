#include <stdint.h>
#include <vector>
#include "sha512.h"

class MerkleTree
{
    protected:
        std::vector<std::array<uint64_t, 8>> mempool;
    
    public:
        std::string MerkleRoot()
        {
            IntTypes int_type = IntTypes();
            uint64_t hashArr[8<<1];
            
            // calculate MerkleTree
            if (mempool.size()%2 == 0) {
                for(int c=0;c<mempool.size();c++) {
                    for(int c=0;c<8;c++) {
                        hashArr[c] = mempoolSingleHash1[c];
                        hashArr[c+8] = mempoolSingleHash2[c];
                    }
                }
            }
            return NULL;
        }
};

class Node : public MerkleTree
{
    
};
