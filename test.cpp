/*
 *  github: kibnakamoto
 *   Created on: Dec. 5, 2021
 *      Author: Taha Canturk
 *       Finalized: Jan. 5 2022
 *        More Info: github.com/kibnakamoto/sha512.cpp/blob/main/README.md
 */

#ifndef SHA512_H_
#define SHA512_H_

#include <string>
#include <cstring>
#include <stdint.h>
#include <iomanip>

// choice = (x ∧ y) ⊕ (¯x ∧ z)
inline uint64_t Ch(uint64_t e, uint64_t f, uint64_t g) {
    return ((e bitand f)xor(~e bitand g));
}

// // majority = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
inline uint64_t Maj(uint64_t a, uint64_t b, uint64_t c) {
    return ((a & b)^(a & c)^(b & c));
}

// // binary operators
inline uint64_t Shr(uint64_t x, unsigned int n) {
    return (x >> n);
}
inline uint64_t Rotr(uint64_t x, unsigned int n) {
    return ( (x >> n)|(x << (sizeof(x)<<3)-n) );
}


// length which is __uint128_t in 2 uint64_t integers
inline std::pair<uint64_t,uint64_t> to2_uint64(__uint128_t source) {
    constexpr const __uint128_t bottom_mask = (__uint128_t{1} << 64) - 1;
    constexpr const __uint128_t top_mask = ~bottom_mask;
    return {source bitand bottom_mask, Shr((source bitand top_mask), 64)};
}

class SHA512
{
    protected:
        // 80 64 bit unsigned constants for sha512 algorithm
        const uint64_t K[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
            0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
            0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
            0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 
            0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
            0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
            0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
            0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
            0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
            0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
            0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
            0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
            0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
            0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
        
        // initialize hash values
        uint64_t H[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                         0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
            
            // transform
            uint64_t* transform(uint64_t* TMP)
            {
                // initialize hash values
                uint64_t V[8];
                memcpy(V, H, sizeof(uint64_t)*8);

                // create message schedule
                for (int c=16;c<80;c++)
                {
                    // σ0 = (w[c−15] ≫≫ 1) ⊕ (w[c−15] ≫≫ 8) ⊕ (w[c−15] ≫ 7)
                    uint64_t s0 = Rotr(TMP[c-15],1) xor Rotr(TMP[c-15],8) xor 
                                       Shr(TMP[c-15],7);
                    
                    // σ1 = (w[c−2] ≫≫ 19) ⊕ (w[c−2] ≫≫ 61) ⊕ (w[c−2] ≫ 6)
                    uint64_t s1 = Rotr(TMP[c-2],19) xor Rotr(TMP[c-2],61) xor 
                                  Shr(TMP[c-2],6);
                    
                    // uint64_t does binary addition 2^64.
                    // w[c] = w[c−16] [+] σ0 [+] w[c−7] [+] σ1
                    TMP[c] = TMP[c-16] + s0 + TMP[c-7] + s1;
                }
                
                for (int c=0;c<80;c++)
                {
                    // Σ0 = (a ≫≫ 28) ⊕ (a ≫≫ 34) ⊕ (a ≫≫ 39)
                    uint64_t S0 = Rotr(V[0], 28) xor Rotr(V[0], 34) xor Rotr(V[0], 39);
                    
                    // T2 = Σ0 + Maj
                    uint64_t temp2 = S0 + Maj(V[0], V[1], V[2]);
                    
                    // Σ1 = (e ≫≫ 14) ⊕ (e ≫≫ 18) ⊕ (e ≫≫ 41)
                    uint64_t S1 = Rotr(V[4], 14) xor Rotr(V[4], 18) xor Rotr(V[4], 41);
                    
                    // T1 = h + Σ1 + Ch[e,f,g] + K[c] + W[c]
                    uint64_t temp1 = V[7] + S1 + Ch(V[4], V[5], V[6]) + K[c] + TMP[c];
                    
                    // modify hash values
                    V[7] = V[6];
                    V[6] = V[5];
                    V[5] = V[4];
                    V[4] = V[3] + temp1;
                    V[3] = V[2];
                    V[2] = V[1];
                    V[1] = V[0];
                    V[0] = temp1 + temp2;
                }
                for(int c=0;c<8;c++) {
                    H[c] += V[c];
                }

                return H;
            }
        
    public:
        uint64_t* Sha512(std::string msg)
        {
        	// length in bytes.
            __uint128_t len = msg.length();
            
            // length is represented by a 128 bit unsigned integer
            __uint128_t bitlen = len << 3;
            
            // padding with zeros
            unsigned int padding = ((1024-(bitlen+1)-128) % 1024)-7; // in bits
            padding /= 8; // in bytes.
            __uint128_t blockBytesLen = padding+len+17;
            uint8_t WordArray[blockBytesLen];
            memset(WordArray, 0, blockBytesLen);
            for (__uint128_t c=0;c<len;c++) {
                WordArray[c] = msg.c_str()[c];
            }
            WordArray[len] = (uint8_t)0x80; // append 10000000.
            
            uint64_t W[blockBytesLen/8];
            // pad W with zeros
            for (int c=0; c<blockBytesLen/8; c++) {
                W[c] = 0x00;
            }
            
            // 8 bit array values to 64 bit array using 64 bit integer array.
            for (int i=0; i<len/8+1; i++) {
                W[i] = (uint64_t)WordArray[i*8]<<56;
                for (int j=1; j<=6; j++)
                    W[i] = W[i]|( (uint64_t)WordArray[i*8+j]<<(7-j)*8);
                W[i] = W[i]|( (uint64_t)WordArray[i*8+7] );
            }
            
            // append 128 bit length as 2 uint64_t's as a big endian
            auto [fst, snd] = to2_uint64(bitlen);
            W[Shr(padding+len+1,3)+1] = fst;
            W[Shr(padding+len+1,3)+2] = snd;
            
            /* multi-block processing start */
            uint64_t TMP[80];
            for(int c=0;c<80;c++) {
                TMP[c] = 0x00;
            }
            
            // multi-block and single block processing
            for(int c=0;c<blockBytesLen/128;c++) {
                for(int i=0;i<16;i++)
                    TMP[i] = W[i+16*c];
                transform(TMP);
            }
            
        	return H;
        }
        
        // for hashing 2 uint64_t pointer hashes. For MerkleTree
        uint64_t* sha512_ptr(uint64_t* hash1, uint64_t* hash2)
        {
            uint64_t W[32];
            uint64_t TMP[80];
            for(int c=0;c<80;c++) {
                TMP[c] = 0x00;
            }
            for(int c=16;c<32;c++) {
                W[c] = 0x00;
            }
            for(int c=0;c<8;c++) {
                W[c] = hash1[c];
                W[c+8] = hash2[c];
            }
            
            // append 1 as 64-bit value
            W[16] = 0x80ULL<<56;
            
            // append bitlen
            W[32-1] = 0x400ULL;
            
            // multi-block processing
            for(int c=0;c<2;c++) {
                for(int i=0;i<16;i++)
                    TMP[i] = W[i+16*c]; // 16 indexes = 1 block of data
                transform(TMP);
            }
            return H;
        }
        
        uint64_t* sha512_single_ptr(uint64_t* singleHash)
        {
            uint64_t W[80];
            for(int c=9;c<80;c++) {
                W[c] = 0x00;
            }
            for(int c=0;c<8;c++) {
                W[c] = singleHash[c];
            }
            
            // append 1 as 64-bit value
            W[8] = 0x80ULL<<56;
            
            // append bitlen
            W[16-1] = 0x200ULL;
            
            // single-block transform
            transform(W);
            
            return H;
            
        }
};

uint64_t* sha512(std::string input) {
    SHA512 hash;
    return hash.Sha512(input);
}

std::string sha512_str(std::string input) {
    std::stringstream ss;
    for (int c=0;c<8;c++) {
        ss << std::setfill('0') << std::setw(16) << std::hex << (sha512(input)[c]|0);
    }
	return ss.str();
}

#endif /* SHA512_H_ */



#include <stdint.h>
#include <tuple>
#include <string.h> // for memcpy

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        // This function is made for 256-bit sha256
        inline std::pair<__uint128_t, __uint128_t> __uint256_t(uint32_t mempoolSingleHash[8])
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
        __uint512_t(uint64_t mempoolSingleHash[8])
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
        __uint1024_t(uint64_t mempoolSingleHash1[8], uint64_t mempoolSingleHash2[8])
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
        inline uint8_t* arr64ToCharArr(uint64_t* mempoolSingleHash1, 
                                   uint64_t* mempoolSingleHash2, uint8_t* hashchArr)
        {
            uint64_t hashArr[8<<1];
            
            for(int c=0;c<8;c++) {
                hashArr[c] = mempoolSingleHash1[c];
                hashArr[c+8] = mempoolSingleHash2[c];
            }
            
            // convert uint64_t array[16] to byte array[128]
            for(int c=0;c<16;c++) {
                hashchArr[c*8] = hashArr[c]>>56 & 0xff;
                hashchArr[c*8+1] = hashArr[c]>>48 & 0xff;
                hashchArr[c*8+2] = hashArr[c]>>40 & 0xff;
                hashchArr[c*8+3] = hashArr[c]>>32 & 0xff;
                hashchArr[c*8+4] = hashArr[c]>>24 & 0xff;
                hashchArr[c*8+5] = hashArr[c]>>16 & 0xff;
                hashchArr[c*8+6] = hashArr[c]>>8 & 0xff;
                hashchArr[c*8+7] = hashArr[c] & 0xff;
            }
            return hashchArr;
        }
        uint64_t* avoidPtr(uint64_t* hash) {
            uint64_t* receiverPtr = new uint64_t[8];
            memcpy(receiverPtr, hash, sizeof(uint64_t)<<3);
            return receiverPtr;
        }
};


/* Author: Taha Canturk
*  Github: Kibnakamoto
*   Repisotory: AES
*  Start Date: March, 5, 2022
*  Finalized: March 11, 2022
*/


#include <iostream>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <iomanip>

class AES
{
    // operations of aes 256, 128, 192
    class OPS_AES
    {
        /* ENCRYPTION/DECRYPTION */
        private:
            // Rijndael's S-box as a 2-dimentional matrix
            const uint8_t sbox[16][16] = {
                {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 
                0x2B, 0xFE, 0xD7, 0xAB, 0x76}, {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
                0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, {0xB7,
                0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
                0x71, 0xD8, 0x31, 0x15}, {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
                0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, {0x09, 0x83,
                0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
                0xE3, 0x2F, 0x84}, {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
                0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, {0xD0, 0xEF, 0xAA,
                0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
                0x9F, 0xA8}, {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
                0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, {0xCD, 0x0C, 0x13, 0xEC,
                0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
                0x73}, {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
                0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, {0xE0, 0x32, 0x3A, 0x0A, 0x49,
                0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
                0xEA, 0x65, 0x7A, 0xAE, 0x08}, {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
                0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, {0x70,
                0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
                0x86, 0xC1, 0x1D, 0x9E}, {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
                0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, {0x8C, 0xA1,
                0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 
                0x54, 0xBB, 0x16}};
            
            // Rijndael's inverse S-box as a 2-dimentional matrix
            const uint8_t inv_sbox[16][16] = {
                {0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54,
                0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb,
                0x42, 0xfa, 0xc3, 0x4e}, {0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8,
                0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab,
                0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45,
                0x6}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 
                0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f,
                0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37,
                0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
                0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc,
                0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
                0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7,
                0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51,
                0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 
                0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
                0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x4,
                0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
                0xc, 0x7d}};
        public:
            // round constant array
            const uint8_t rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                                      0x40, 0x80, 0x1b, 0x36};

            
            // Galois Field Multipication 2^8
            uint8_t GF256(uint8_t x, uint8_t y)
            {
                /* implemented with bitmasking for efficient and safe 
                   cryptographical use. */
                uint8_t p=0;
                for(int c=0;c<8;c++) {
                    p ^= (uint8_t)(-(y&1)&x);
                    x = (uint8_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
                    y >>= 1;
                }
                return p;
            }
            
            // bitwise circular-left-shift operator for rotating by 8 bits.
            uint32_t rotword(uint32_t x)
            {
                return (x<<8)|(x>>32-8);
            }
            
            /* ENCRYPTION */
            uint8_t** subBytes(uint8_t** b, uint8_t Nb)
            {
                /* seperates hex byte into 2 4 bits and use them as index to
                   sub in values as index of s-box */
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = b[r][c] & 0x0fU;
                        uint8_t high_mask = b[r][c] >> 4;
                        b[r][c] = sbox[high_mask][low_mask];
                    }
                }
                return b;
            }
            
            // shifting rows
            uint8_t** shiftrows(uint8_t** state, uint8_t Nb)
            {
               // to stop values from overriding, use 2 arrays with the same values
               uint8_t pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       pre_state[r][c] = state[r][c];
               }
                // ShiftRows operation. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = pre_state[r][(r+c)%4];
                }
                return state;
            }
            
            uint8_t** mixcolumns(uint8_t** state, uint8_t Nb)
            {
                // lambda function xtime
                auto xtime = [] (uint8_t x)
                {
                    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
                };
                
                for(int c=0;c<Nb;c++) {
                    // create temporary array to stop overriding
                    uint8_t tmpS[4] = {state[0][c], state[1][c], state[2][c], 
                                       state[3][c]};
                    
                    // MixColumns operation from AES proposal
                    uint8_t Tmp = (tmpS[0] ^ tmpS[1] ^ tmpS[2] ^ tmpS[3]);
                    uint8_t Tm =  (tmpS[0] ^ tmpS[1]) ; Tm = xtime(Tm); 
                    state[0][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[1] ^ tmpS[2]) ; Tm = xtime(Tm); 
                    state[1][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[2] ^ tmpS[3]) ; Tm = xtime(Tm);
                    state[2][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[3] ^ tmpS[0]) ; Tm = xtime(Tm);
                    state[3][c] ^=  (Tm ^ Tmp);
                }
                return state;
            }
            
        private:
            uint32_t sub_int(uint32_t y)
            {
                return sbox[(y&0xff)>>4][y&0x0fU];
            }
            
        public:
            uint32_t subword(uint32_t x)
            {
                return (sub_int(x>>24)<<24) | (sub_int((x>>16)&0xff)<<16) |
                       (sub_int((x>>8)&0xff)<<8) | (sub_int(x&0xff)); 
            }
            
            uint8_t** addroundkey(uint8_t** state, uint32_t* w, uint32_t rnd,
                                  uint8_t Nb)
            {
                for(int c=0;c<Nb;c++) {
                    uint32_t w_index = w[rnd*4+c];
                    state[0][c] ^= (w_index >> 24) & 0xff;
                    state[1][c] ^= (w_index >> 16) & 0xff;
                    state[2][c] ^= (w_index >> 8) & 0xff;
                    state[3][c] ^= w_index & 0xff;
                }
                return state;
            }
        
            /* DECRYPTION */
            
            uint8_t** inv_subBytes(uint8_t** state, uint8_t Nb)
            {
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = state[r][c] & 0x0fU;
                        uint8_t high_mask = state[r][c] >> 4;
                        state[r][c] = inv_sbox[high_mask][low_mask];
                    }
                }
                return state;
            }
            
            uint8_t** inv_shiftrows(uint8_t** state, uint8_t Nb)
            {
                // to stop values from overriding, duplicate matrix
               uint8_t inv_pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       inv_pre_state[r][c] = state[r][c];
               }
                

                // shift rows. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][(r+c)%4] = inv_pre_state[r][c];
                }
                return state;
            }
            
            uint8_t** inv_mixcolumns(uint8_t** state, uint8_t Nb)
            {
                uint8_t s_mixarr[4] = {0x0e, 0x0b, 0x0d, 0x09};
                for(int c=0;c<Nb;c++) {
                    // to stop matrix from overriding, use temporrary array
                    uint8_t tmp_state[4] = {state[0][c], state[1][c], state[2][c],
                                            state[3][c]};
                    state[0][c] = (GF256(tmp_state[0], s_mixarr[0]) ^
                                   GF256(tmp_state[1], s_mixarr[1]) ^
                                   GF256(tmp_state[2], s_mixarr[2]) ^
                                   GF256(tmp_state[3], s_mixarr[3]));
                    state[1][c] = (GF256(tmp_state[0], s_mixarr[3]) ^
                                   GF256(tmp_state[1], s_mixarr[0]) ^
                                   GF256(tmp_state[2], s_mixarr[1]) ^
                                   GF256(tmp_state[3], s_mixarr[2]));
                    state[2][c] = (GF256(tmp_state[0], s_mixarr[2]) ^
                                   GF256(tmp_state[1], s_mixarr[3]) ^
                                   GF256(tmp_state[2], s_mixarr[0]) ^
                                   GF256(tmp_state[3], s_mixarr[1]));
                    state[3][c] = (GF256(tmp_state[0], s_mixarr[1]) ^
                                   GF256(tmp_state[1], s_mixarr[2]) ^ 
                                   GF256(tmp_state[2], s_mixarr[3]) ^
                                   GF256(tmp_state[3], s_mixarr[0]));
                }
                return state;
            }
            
        protected:
           // KeyExpansion
           uint32_t* keyExpansion(uint8_t* key, uint32_t* w, uint8_t Nb,
                                  uint8_t Nk, uint8_t Nr)
            {
                uint32_t temp;
                int i=0;
                do {
                    w[i] = ((uint32_t)key[4*i]<<24) | (key[4*i+1]<<16) |
                           (key[4*i+2]<<8) | key[4*i+3];
                    i++;
                } while(i<Nk);
                i=Nk;
                
                // rcon values. initialize twice so it doesn't override
                uint32_t tmp_rcon[11];
                for(int c=1;c<11;c++) {
                    tmp_rcon[c] = (uint8_t)(rcon[c] & 0xff)<<24;
                }
                
                while(i<Nb*(Nr+1)) {
                    temp = w[i-1];
                    if(i%Nk == 0) {
                        temp = subword(rotword(temp)) ^ (uint32_t)tmp_rcon[i/Nk];
                    }
                    else if(Nk>6 && i%Nk == 4) {
                        temp = subword(temp);
                    }
                    w[i] = temp ^ w[i-Nk];
                    i++;
                }
                return w;
            }
            
            uint8_t* cipher(uint8_t* input, uint8_t* output, uint32_t* w, 
                            uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // put 1-dimentional array values to a 2-dimentional matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                // call functions to manipulate state matrix
                addroundkey(state, w, 0, Nb);
                for(int rnd=1;rnd<Nr;rnd++) {
                    subBytes(state, Nb);
                    shiftrows(state, Nb);
                    mixcolumns(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                }
                subBytes(state, Nb);
                shiftrows(state, Nb);
                addroundkey(state, w, Nr, Nb);
            
                // copy state array to output
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                for(int c=0;c<4;c++) {
                   delete[] state[c];
                }
                delete[] state;
                return output;
            }
            
            std::string encrypt(std::string user_in,uint8_t* key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare arrays
                uint8_t input[4*Nb];
                uint8_t output[4*Nb];
                uint32_t w[Nb*(Nr+1)]; // key schedule
                
                // append user input to 1-dimentional array
                for(int c=0;c<4*Nb;c++) {
                    input[c] = user_in[c];
                }
                
                // call KeyExpansion and Cipher function
                keyExpansion(key, w, Nb, Nk, Nr);
                cipher(input, output, w, Nb, Nk, Nr);

                // convert output array to hex string
                std::stringstream ss;
                for (int c=0;c<4*Nb;c++)
                {
                    ss << std::setfill('0') << std::setw(2) << std::hex
                       << (uint16_t)output[c];
                }
            	return ss.str();
            }
            
            uint8_t* invCipher(uint8_t* input, uint8_t* output, uint32_t* w,
                               uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix as a 2d C++ pointer
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // 1d input to 2d matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                addroundkey(state, w, Nr, Nb);
                for(int rnd=Nr-1;rnd>0;rnd--) {
                    inv_shiftrows(state, Nb);
                    inv_subBytes(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                    inv_mixcolumns(state, Nb);
                }
                
                inv_shiftrows(state, Nb);
                inv_subBytes(state, Nb);
                addroundkey(state, w, 0, Nb);
                
                // 2d array to 1d array
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                return output;
            }
            
            std::string decrypt(std::string user_in, uint8_t* key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare single-dimentional arrays
                uint8_t output[4*Nb];
                uint8_t input[4*Nb];
                uint32_t w[Nb*(Nr+1)];
                std::stringstream conv;
                for(int c=0;c<user_in.length();c+=2) {
                    conv << std::hex << user_in.substr(c,2);
                    int32_t uint8;
                    conv >> uint8;
                    input[c/2] = uint8 & 0xffU;
                    conv.str(std::string());
                    conv.clear();
                }
                
                // create key schedule and decrypt
                keyExpansion(key, w, Nb, Nk, Nr); 
                invCipher(input, output, w, Nb, Nk, Nr); // output wrong 
                std::string str = "";
                for(int c=0;c<4*Nb;c++) {
                    str += output[c]; /* Check invCipher */
                }
                return str;
            }
        public:
            std::string multi_block_process_enc(std::string user_in, uint8_t*
                                                key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                // pad message so that length is a multiple of block size(16)
                uint32_t msg_blen = user_in.length() + 16-user_in.length()%16;
                if(user_in.length()%16 == 0) {
                    msg_blen-=16;
                }
                std::stringstream ss;
                ss << user_in << std::setfill('0') << std::setw(msg_blen) << "";
                std::string new_input[msg_blen/16];
                int32_t k=-1;
                std::string final_val = "";
                
                // seperate message into blocks of 16
                for(int c=0;c<msg_blen;c+=16) {
                    k++;
                    if(k<msg_blen/16) {
                        new_input[k] = ss.str().substr(c,16);
                    }
                }
                for(int c=0;c<msg_blen/16;c++) {
                    final_val += encrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
            
            std::string multi_block_process_dec(std::string user_in, uint8_t* 
                                                key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                std::string new_input[user_in.length()/32];
                int k=-1;
                std::string final_val = "";
                
                // input length has to be a multiple of 16 bytes
                if(user_in.length()%32 != 0) {
                    std::cout << "ERROR:\tlength is not a multiple of 32";
                    exit(EXIT_FAILURE);
                }
                
                // seperate message into blocks of 32 hex digits
                for(int c=0;c<user_in.length();c+=32) {
                    k++;
                    new_input[k] = user_in.substr(c,32);
                }
                k=user_in.length()/32;
                for(int c=0;c<k;c++) {
                    final_val += decrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
    };
    
    public:
    class AES128
    {
        // AES algorithm size for AES128
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 4;
            const uint8_t Nr = 10;
        public:
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
    
    class AES192
    {
        // AES algorithm size for AES192
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 6;
            const uint8_t Nr = 12;
        public:
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
        
    };
    
    class AES256
    {
        // AES algorithm size for AES256
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 8;
            const uint8_t Nr = 14;
        public:
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
};


#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

namespace MerkleTree
{
        std::vector<uint64_t*> merkleRoots;
        
        void MerkleRoot(std::vector<uint64_t*> mempool, uint64_t* merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            uint64_t len = mempool.size();
            uint64_t currlen = len;
            bool odd = true;
            bool divisible;
            if(len%2 == odd) { // make sure len is not odd
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++;
            }
            uint64_t divCurrlen = len;
            bool divs;
            int amountofLoop = 0;
            while (divCurrlen != 0) {
                divCurrlen /= 2;
                amountofLoop++;
                for(int c=0;c<amountofLoop*2;c++) {
                    uint64_t* oddZfill = new uint64_t[8];
                    oddZfill = sha512("00000000");
                    mempool.push_back(oddZfill);
                    len++; // update len
                }
                divs = (divCurrlen/2) % 2 == 0;
                if(divs != true) {
                    mempool.push_back(oddZfill);
                    len++; // update len
                }
                std::cout << "\n\n" << divCurrlen << "\n\n";
            }
            std::cout << "\nlen:\t" << std::dec << len << "\n\n";
            
            // calculate MerkleRoot
            // while(currlen >= 0) {
                
                
                // update current length of leaves until MerkleRoot
            //     currlen /= 2;
            //     j++;
            // }
        }
}; // namespace MerkleTree


/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: N/A
*
* This implementation only works for C++ version 17 or above. 
* C++ 14 also works but gives warning
* 
*/

#include <iostream>
#include <string>
#include <random>
#include <time.h>
#include <tuple>
#include <map>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"
#include "AES.h" // Symmetrical Encryption

// 256-bit random number. AES key
uint8_t* GenerateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    uint8_t* key = nullptr;
    key = new uint8_t[32];
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
      std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<32-4;c++) {
        uint32_t tmp = distr(generator);
        key[c] = tmp>>24 & 0xff;
        key[c+1] = tmp>>16 & 0xff;
        key[c+2] = tmp>>8 & 0xff;
        key[c+3] = tmp & 0xff;
    }
    return key;
}


struct Transaction {
    uint64_t* sender = new uint64_t[8];
    uint64_t* receiver = new uint64_t[8];
    uint32_t amount;
    
    std::string encryptTr(uint8_t* key)
    {
        AES::AES256 aes256;
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return aes256.encrypt(transactionData, key);
    }
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<uint64_t*,std::vector<uint8_t*>> walletData)
    {/* not tested */
        /* walletData = map to verify if owner of the wallet is requesting data dump
           uint64_t* is WalletAddress and vector of uint8_t* is the string AES key
           used as plain text and the AES key used as an AES key.
           walletData vector has length 2 and key used as key is first and 
           string key as uint8_t* is second
        */
        // useless function. Delete if not useful as reference
        std::cout << std::endl << std::endl;
        AES::AES256 aes256;
        std::string AESkeyStr = "";
        std::string AES256_ciphertext = "";
        for (auto const& [key, val] : walletData) {
            for(int c=0;c<32;c++) {
            AESkeyStr += std::to_string(val[1][c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
            for(int i=0;i<8;i++) {
                if(sha512(AES256_ciphertext)[i] != key[i]) {
                    std::cout << "wallet Data mismatch";
                    exit(EXIT_FAILURE);
                }
            }
            std::cout << std::endl << std::endl << "AES256 key:\t";
            for(int c=0;c<32;c++) {
                std::cout << val[1][c];
            }
            std::cout << std::endl << std::endl;
        }
        std::cout << "sender\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << sender[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "receiver\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << receiver[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "amount:\t" << amount;
        std::cout << std::endl << std::endl;
    }
    
    // A single hashed transaction data
    uint64_t* Hash()
    { /* if parameter is a raw pointer instead of array. It's wrong */
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return sha512(transactionData);
    }
};

class WalletAddress
{
    public:
        std::pair<uint64_t*, std::vector<uint8_t*>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        { // make it a pair function that returns both aes key and ciphertext hash
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            AES::AES256 aes256;
            uint8_t* AESkey = nullptr;
            AESkey = new uint8_t[32];
            AESkey = GenerateAES256Key(); // 32 bytes
            uint8_t* NewAESkey = nullptr;
            NewAESkey = new uint8_t[32];
            NewAESkey = GenerateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump AES-key") {
                std::cout << std::endl << "AES256 key:\t";
                for(int c=0;c<32;c++) {
                    std::cout << AESkey[c];
                }
                std::cout << std::endl << std::endl;
            }
            std::vector<uint8_t*> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {int_type.avoidPtr(sha512("abc")), keys}; // 2a9ac94fa54ca49f
        }
};

union Wallet {
    // parameters to verify owner of the wallet is modifying
    static uint64_t* walletAddress; // should be nullptr if WalletAddressNotFound
    static std::vector<uint8_t*> AESkeysWallet; // can be empty if WalletAddressNotFound
    
    /* verifyInfo includes password as third index, AESkeysWallet in the first 
       and second index. If they don't match, don't change anything on the Wallet */
    static std::map<uint64_t*, std::vector<uint8_t*>> verifyInfo;
    class WA
    {
        protected:
            std::vector<uint8_t*> AESkeysTr;
            std::vector<std::string> ciphertexts;
            std::vector<uint64_t*> transactionhashes;
            int32_t storedCrypto = 0; // can be negative
        
        public:
            void verifyOwnerData(const std::map<uint64_t*,std::vector<uint8_t*>>
                                 walletData)
            {
                AES::AES256 aes256;
                std::string AESkeyStr = "";
                std::string AES256_ciphertext = "";
                for (auto const& [key, val] : walletData) {
                    for(int c=0;c<32;c++) {
                        AESkeyStr += std::to_string(val[1][c]);
                    }
                    AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
                    for(int i=0;i<8;i++) {
                        if(sha512(AES256_ciphertext)[i] != key[i]) {
                            std::cout << "\nwallet data mismatch";
                            exit(EXIT_FAILURE);
                        } else {
                            std::cout << "\n\nwallet data verified\n\n";
                        }
                    }
                }
            }
            
            void WalletAddressNotFound()
            {
                WalletAddress wallet_address = WalletAddress();
                std::cout << "No wallet address found!\n";
                std::cout << "Generating Wallet Address\n";
                auto [fst, snd] = wallet_address.GenerateNewWalletAddress();
                walletAddress = fst;
                AESkeysWallet = snd;
                std::cout << "Wallet Address Generated\nWallet Address:\t";
                for(int c=0;c<8;c++) {
                    std::cout << std::hex << walletAddress[c];
                }
                std::cout << "\n\ntrying again";
                
            }
            // append crypto to the wallet
            void appendCrypto(uint32_t amount)
            {
                if(walletAddress == nullptr) {
                    WalletAddressNotFound(); // if wallet not created
                } else {
                    verifyOwnerData(verifyInfo);
                }
                storedCrypto += amount;
            }
            
            void subtractCrypto(uint32_t amount)
            {
                verifyOwnerData(verifyInfo);
                if(amount > storedCrypto) {
                    std::cout << "you do not own " << amount << ". Process failed";
                    exit(EXIT_FAILURE);
                } else if(walletAddress == nullptr) {
                    std::cout << "\naccount not found\n";
                    exit(EXIT_FAILURE);
                }
                storedCrypto -= amount;
            }
            
            // if new transaction added to the Wallet
            void newTransaction(uint64_t* sender, uint64_t* receiver, 
                                uint32_t amount, std::vector<uint64_t*> 
                                mempool)
            {
                if(walletAddress != nullptr) {
                    verifyOwnerData(verifyInfo);
                    struct Transaction trns{sender, receiver, amount};
                    transactionhashes.push_back(trns.Hash());
                    storedCrypto -= amount;
                    uint8_t* newAES_TrKey = nullptr;
                    newAES_TrKey = new uint8_t[32];
                    newAES_TrKey = GenerateAES256Key();
                    ciphertexts.push_back(trns.encryptTr(newAES_TrKey));
                    AESkeysTr.push_back(newAES_TrKey);
                    mempool.push_back(transactionhashes[transactionhashes.size()]);
                } else {
                    std::cout << "\nERR:\tWalletAddressNotFound\n";
                    WalletAddressNotFound();
                    std::cout << "\nNew Wallet Address Created\n";
                    newTransaction(sender, receiver, amount, mempool);
                    std::cout << "\nTransaction complete";
                    std::cout << std::endl << std::endl;
                }
            }
    };
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    WalletAddress wallet_address = WalletAddress();
    SHA512 hash = SHA512();
    AES::AES128 aes128;
    AES::AES192 aes192;
    AES::AES256 aes256;
    uint64_t* merkle_root = new uint64_t[8]; // declare Merkle Root
    uint64_t* walletAddress = new uint64_t[8];
    std::vector<uint64_t*> mempool; // declare mempool
    std::vector<uint64_t*> walletAddresses; // All wallet addresses
    struct Transaction trns{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            50000};
    struct Transaction trns1{int_type.avoidPtr(sha512("sener")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            54000};
    struct Transaction trns2{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("reciver")), // TODO: fix
                            35600};
    
    struct Transaction trns3{int_type.avoidPtr(sha512("nder")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            50000};
    struct Transaction trns4{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            40000};
    mempool.push_back(trns.Hash());
    /* TEST MERKLEROOT */
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 5 transactions
    mempool.push_back(trns.Hash());
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 10 transactions
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 14 transactions
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 18 transactions
    /* TEST MERKLEROOT */
    MerkleTree::MerkleRoot(mempool, merkle_root);
    auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    walletAddress = fst;
    walletAddresses.push_back(fst);
    delete[] snd[0];
    delete[] snd[1];
    for(int c=0;c<8;c++) {
        // std::cout << std::hex << walletAddress[c] << " ";
        std::cout << std::hex << trns.Hash()[c] << " ";
    }
    return 0;
}
