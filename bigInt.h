#include <stdint.h>

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        /* this 256-bit unsigned int turns each transaction of the mempool 
           into 1 numerical variable */
        inline std::pair<__uint128_t, __uint128_t> __uint256_t(uint64_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>1];
            
            // convert 2 64-bit unsigned int to 1 128-bit unsigned int
            // c<8 because mempoolSingleHash is an array of length 8
            for(int c=0;c<4;c++) {
                arr128[c] = (__uint128_t)(((__uint128_t)mempoolSingleHash[c*2]<<
                                           64) | (mempoolSingleHash[c*2+1]));
            }
            for(__uint128_t c : arr128) {

            }
            // return 2 arr128 var at once
            return {(arr128[0]<<64)|arr128[1], (arr128[2]<<64)|arr128[3]};
        }
        /* this function converts uint64_t array[8] to a single __uint512_t variable
           since there is no size of integers, I had to concatinate them to 
           that size instead of creating a variable that size */
        inline std::pair<__uint128_t, __uint128_t> __uint512_t(uint64_t mempoolSingleHash[8])
        {
            return {
                (__uint128_t)(((__uint128_t)mempoolSingleHash[0]<<48) | 
                (mempoolSingleHash[1]<<32)) | (__uint128_t)((
                (__uint128_t)mempoolSingleHash[2]<<16) | (mempoolSingleHash[3])), 
                (__uint128_t)(((__uint128_t)mempoolSingleHash[4]<<48) | 
                (mempoolSingleHash[5]<<32)) | (__uint128_t)((
                (__uint128_t)mempoolSingleHash[6]<<16) | (mempoolSingleHash[7]))
                // (__uint128_t)(((__uint128_t)mempoolSingleHash[0]<<64) | 
                // (mempoolSingleHash[1])) | (__uint128_t)((
                // (__uint128_t)mempoolSingleHash[2]<<64) | (mempoolSingleHash[3])), 
                // (__uint128_t)(((__uint128_t)mempoolSingleHash[4]<<64) | 
                // (mempoolSingleHash[5])) | (__uint128_t)((
                // (__uint128_t)mempoolSingleHash[6]<<64) | (mempoolSingleHash[7]))
            };
        }
        // TODO: define 1024 bit int for 2 distinct mempoolSingleHash arrays. 
        // Use this in the sha512 merkle tree.
        
};
