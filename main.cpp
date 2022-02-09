#include <iostream>
#include <string>
#include "__uint256_t.h"
#include "sha512.h"

int main()
{
    /* iterate each value of mempool using this method, replace string abc 
       with the that needs to be hashed. Since mempool is a hash array, no 
       need to hash it again */
    uint64_t SingleMempoolHash[8];
    memcpy(SingleMempoolHash, sha512("abc"), sizeof(uint64_t)<<3);
    
    IntTypes bigInt = IntTypes();
    bigInt.__uint256_t(SingleMempoolHash);
    return 0;
}
