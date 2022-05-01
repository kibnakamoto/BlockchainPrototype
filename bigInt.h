/* Author: Taha Canturk
*  Github: Kibnakamoto
*   Repisotory: bigInt
*  Start Date: Feb, 9, 2022
*  Last Update: May 1, 2022
*/


#include <stdint.h>
#include <tuple>
#include <string.h> // for memcpy
#include <memory>

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        // This function is made for 256-bit sha256
        inline std::pair<__uint128_t, __uint128_t> __uint256_pair(uint32_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>2];
            
            // convert each 4 32-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<2;c++) {
                arr128[c] = (((__uint128_t)mempoolSingleHash[c*4]<<96) |
                             ((__uint128_t)mempoolSingleHash[c*4+1]<<64) |
                             ((__uint128_t)mempoolSingleHash[c*4+2]<<32) |
                             (__uint128_t)mempoolSingleHash[c*4+3]);
            }
            return {arr128[0], arr128[1]};
        }
        /* this creates a tuple of 4 variables that are 128-bit each and 
           stores 512-bit unsigned int data */
        inline std::tuple<__uint128_t, __uint128_t,__uint128_t, __uint128_t>
        __uint512_tuple(uint64_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>1];
            
            // convert each 2 64-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<4;c++) {
                arr128[c] = (((__uint128_t)mempoolSingleHash[c*2]<< 64) |
                             ((__uint128_t)mempoolSingleHash[c*2+1]));
            }
            return {arr128[0], arr128[1], arr128[2], arr128[3]};
        }
        
        // converts 2 array[8] of 64-bit unsigned int into 1 1024 bit tuple
        inline std::tuple<__uint128_t, __uint128_t,__uint128_t, __uint128_t,
                          __uint128_t, __uint128_t,__uint128_t, __uint128_t>
        __uint1024_tuple(uint64_t mempoolSingleHash1[8], uint64_t mempoolSingleHash2[8])
        {
            // test function
            __uint128_t arr128[8];
            uint64_t hashArr[8<<1];
            for(int c=0;c<8;c++) {
                hashArr[c] = mempoolSingleHash1[c];
                hashArr[c+8] = mempoolSingleHash2[c];
            }
            // convert each 4 32-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<8;c++) {
                arr128[c] = (((__uint128_t)hashArr[c*2]<< 64) |
                             ((__uint128_t)hashArr[c*2+1]));
            }
            return {arr128[0], arr128[1], arr128[2], arr128[3], arr128[4], 
                    arr128[5], arr128[6], arr128[7]};
        }
        
        // uint64_t array of 8 to uint8_t array of 64. This is for the Merkle Tree
        inline std::shared_ptr<uint8_t> arr64ToCharArr(std::shared_ptr<uint64_t>
                                                       mempoolSingleHash1,
                                                       std::shared_ptr<uint64_t>
                                                       mempoolSingleHash2)
        {
            std::shared_ptr<uint64_t> hashArr(new uint64_t[16]);
            std::shared_ptr<uint8_t> hashchArr(new uint8_t[128]);
            
            for(int c=0;c<8;c++) {
                hashArr.get()[c] = mempoolSingleHash1.get()[c];
                hashArr.get()[c+8] = mempoolSingleHash2.get()[c];
            }
            
            // convert uint64_t array[16] to byte array[128]
            // for(int c=0;c<16;c++) {
            //     hashchArr.get()[c*8] = hashArr.get()[c]>>56 & 0xff;
            //     hashchArr.get()[c*8+1] = hashArr.get()[c]>>48 & 0xff;
            //     hashchArr.get()[c*8+2] = hashArr.get()[c]>>40 & 0xff;
            //     hashchArr.get()[c*8+3] = hashArr.get()[c]>>32 & 0xff;
            //     hashchArr.get()[c*8+4] = hashArr.get()[c]>>24 & 0xff;
            //     hashchArr.get()[c*8+5] = hashArr.get()[c]>>16 & 0xff;
            //     hashchArr.get()[c*8+6] = hashArr.get()[c]>>8 & 0xff;
            //     hashchArr.get()[c*8+7] = hashArr.get()[c] & 0xff;
            // }
            
            for(int c=0;c<16;c++) {
                for(int i=56,k=0;i>=0,k<8;i-=8,k++) {
                    hashchArr.get()[c*8+k] = hashArr.get()[c]>>i & 0xff;
                }
            }

            return hashchArr;
        }
};
