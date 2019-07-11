#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <assert.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/mat_ZZ.h>
#include <gmp.h>

#include "params.h"
#include "FFT.h"
#include "Sampling.h"
#include "Random.h"
#include "Algebra.h"
#include "DigitalSignature.h"
#include "KEM.h"
#include "cpucycles.h"

#include <openssl/sha.h>
#include "huffman.h"
#include "json.hpp"
#include "crypto++/aes.h"
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>


using namespace std;
using namespace NTL;
using json = nlohmann::json;

typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption CBC_ENC;
typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption CBC_DEC;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using CryptoPP::SecByteBlock;


/**
 * Deserializes string and returns a ZZX
 * @param string serialArray has format "[12 535 7542 213 ...]"
 * @return ZZX
 */
ZZX stringToZZX(string serialArray){
	serialArray.erase(0,1);
	serialArray.erase(serialArray.size()-1);
	// cout << "\nstring: " << serialArray;
	size_t num = std::count(serialArray.begin(), serialArray.end(), ' ');
	ZZX zzx;
	zzx.SetLength(num+1);
	stringstream stream(serialArray);
	int n;
	int count = 0;
	while(stream >> n){
		zzx[count]=n;
		count++;
	}
	return zzx;
}

/**
 * Takes in NTL objects and puts them into a json for sigma1 message
 * @param Alice verification key (should have been gotten beforehand..), Alice m2, Alice s1,s2 array
 * @return a json for sigma1 
 */
static json sigmaOneJson(ZZ_pX Kv_a, vec_ZZ m2_a, ZZX s_a[2]){ //Kv_a should be gotten beforehand...
	json j;
	j["STATE"] = "SIGMA1";
	std::stringstream temp;

	temp << Kv_a; //Alice public key
	j["Kv_a"] = temp.str();

	temp.str(std::string()); //clear the stringstream
	temp.clear();

	temp << s_a[0];
	j["s_a[0]"] = temp.str();

	temp.str(std::string()); //clear the stringstream
	temp.clear();

	temp << s_a[1];
	j["s_a[1]"] = temp.str();

	temp.str(std::string()); //clear the stringstream
	temp.clear();

	temp << m2_a;
	j["m2_a"] = temp.str();

	return j;
}


/**
 * Takes in NTL objects and puts them into a json for sigma2 message
 * @param Bob s1,s2 array, Bob m2
 * @return a json for sigma2
 */
static json sigmaTwoJson(ZZX s_b[2], vec_ZZ m2_b){
	json j;
	j["STATE"] = "SIGMA2";
	std::stringstream temp;

	temp << s_b[0];
	j["s_b[0]"] = temp.str();

	temp.str(std::string()); //clear the stringstream
	temp.clear();

	temp << s_b[1];
	j["s_b[1]"] = temp.str();

	temp.str(std::string()); //clear the stringstream
	temp.clear();

	temp << m2_b;
	j["m2_b"] = temp.str();

	return j;
}


string encrypt(string& plain, CBC_ENC &cipher)
{
    string c;
    try
    {
        CryptoPP::StringSource( plain, true,
            new CryptoPP::StreamTransformationFilter( cipher,
                new CryptoPP::StringSink( c )
            ) 
        );
    }catch( CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    return c;
   
}

string decrypt( unsigned char &key, string& cipher, unsigned char iv[AES::BLOCKSIZE])
{
    string recovered;
    try
    {
		CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d;
        d.SetKeyWithIV( &key, 32, iv);
        
        CryptoPP::StringSource( cipher, true,
            new CryptoPP::StreamTransformationFilter( d,
                new CryptoPP::StringSink(recovered)
            )
        ); 
        
        // cout << "recovered text: " << recovered << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}

void Hash2(vec_ZZ& Auth, vec_ZZ Ke,vec_ZZ c,vec_ZZ k){
    SHA256_CTX ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);

    //vec_ZZ msg = RandomVector();
    Auth.SetLength(32);
    for(int i = 0; i < N0; i++) {
        char f = (conv<int>(Ke[i]+c[i]+k[i])%255);
        SHA256_Update(&ctx, &f, 1);
    }
    SHA256_Final(digest, &ctx);

    for(int i=0; i < 32 and i < N0; i++){
        //cout << int(digest[i]) << " ";
        Auth[i] = conv<ZZ>(digest[i])%q0;
    }

}


void Hash1(vec_ZZ& sk, vec_ZZ Ke,vec_ZZ c_Auth, vec_ZZ k){
    SHA256_CTX ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, "K", 1);

    //vec_ZZ msg = RandomVector();
    sk.SetLength(32);
    for(int i = 0; i < N0; i++) {
        char f = (conv<int>(Ke[i]+c_Auth[i]+k[i])%255);
        SHA256_Update(&ctx, &f, 1);
    }
    SHA256_Final(digest, &ctx);

    for(int i=0; i < 32 and i < N0; i++){
        //cout << int(digest[i]) << " ";
        sk[i] = conv<ZZ>(digest[i])%q0;
    }
}