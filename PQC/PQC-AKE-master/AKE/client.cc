#define _BSD_SOURCE
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

using namespace std;
using namespace NTL;
using json = nlohmann::json;
int retries = 0;


#define BACKLOG 10 // how many pending connections queue will hold
#define bufSize 1024*32 //32kB
//CLIENT IS ALICE

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

int main(int argc, char* argv[])	{

	//PQC SETUP
	clock_t t1,t2;
	float ta_ds_keygen, ta_kem_keygen, ta_ds_sig, ta_ds_ver, ta_kem_dec, ta_h2, ta_h1, ta_total1, ta_total2;
	unsigned long long c1,c2;
 	long long ca_ds_keygen, ca_kem_keygen, ca_ds_sig, ca_ds_ver, ca_kem_dec, ca_h2, ca_h1, ca_total1, ca_total2;


	//Alice and Bob Generate SigKeyGen (Previous to actual AKE Exchange)
	ZZX 	Ks_a[2];
	ZZ_pX 	Kv_a , Kv_b;

	MSK_Data * MSKD_a = new MSK_Data;													//ALice: (Ks1,Kv1) <- SigKeyGen

	t1 = clock();
	c1 = cpucycles();
	SigKeyGen(Ks_a,Kv_a,MSKD_a);														//ALICE: sk(1) <- BOT
	c2 = cpucycles();
	t2 = clock();
	ca_ds_keygen = c2-c1;
	ta_ds_keygen = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
		
	//Alice
	vec_ZZ sk_a;
	ZZX Kd_a, Ke_a_temp, Kd_inv2_a;

		t1 = clock();
		c1 = cpucycles();
	KEMKeyGen(Kd_a,Ke_a_temp, Kd_inv2_a);															//ALICE: (Kd,Ke) <- KEMKeyGen
		c2 = cpucycles();
		t2 = clock();
		ca_kem_keygen = c2-c1;
		ta_kem_keygen = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
	vec_ZZ Ke_a = conv<vec_ZZ>(Ke_a_temp); //public key for alice

	vec_ZZ r_a;
	ZZX s_a[2];
	vec_ZZ m2_a;

	t1 = clock();
	c1 = cpucycles();
	//TODO
	Sign2(s_a,m2_a,Ke_a,MSKD_a); //Ks_a == MSKD_a which contains f,g 						//ALICE: simga1 <- Sig(Ks1,Ke)
								//s1 => renamed as s2 will be inside s_a[1]

	c2 = cpucycles();
	t2 = clock();
	ca_ds_sig = c2-c1;
	ta_ds_sig = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

		//cout << "S:" << deg(s_a[1]) << Ke_a<< "\n";




	sockaddr_in my_addr;
	int sockfd;
	

	my_addr.sin_family = AF_INET; // host byte order
	my_addr.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1],(in_addr*)&(my_addr.sin_addr));
	memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct
	
	sockfd = socket (PF_INET, SOCK_STREAM, 0); 	
	connect(sockfd, (struct sockaddr *)&my_addr,sizeof(struct sockaddr));

	
	// char welcome[bufSize];
	// recv(sockfd,welcome,bufSize,0);
	// cout<<"Server Message : "<<welcome<<endl;		
	
	char buffer[bufSize];
	char receive[bufSize];


	json jsonSend;
	json jsonReceive;
	string state = "NULL";
	string jDump;

	while(true)	{
		recv(sockfd,receive,bufSize,0);
		if(receive[0] == '\0'){
			// cout << "received nothing?\n";
			continue;
		}
		cout<<"Server Message : "<<receive<<endl;
		jsonReceive = json::parse(receive);
		state = jsonReceive.value("STATE", "NULL");
		
		if(state=="CONNECT"){

			Kv_b = conv<ZZ_pX>(stringToZZX(jsonReceive.value("Kv_b", "NULL")));
			jsonSend = sigmaOneJson(Kv_a, m2_a, s_a); //Kv_a should be gotten beforehand...
			jDump = jsonSend.dump(); //serialize the json
			send(sockfd,jDump.c_str(),jDump.length()+1,0);
			continue;

		}
		else if(state=="SIGMA2"){

			continue;
		}
		else if(state=="NULL"){
			cout << "NO STATE OR STATE == \"NULL\"\n";
			continue;
		}
		// cout<<"Enter message for server : ";
		// cin.getline(buffer,bufSize);
		// j["key"] = buffer;

		//Alice sends Sigma1 to Bob 															//AlICE ----> simga1 = <Ke>1 ----> Bob
			// Aka. Bob has access only to:
			// - s_a[1] ] 
			// - Ke_a   ]  -- Sent from Alice
			// - r_a    ] 
			// - Kv_a   ]--- (Public) Obtained before hand.
		// cout << "\nTransmitting (A->b)\n";
		// cout << " +    Ke_a : " << Ke_a.length()*16 << "\n";
		// cout << " +   s1,s2 : " << conv<vec_ZZ>(s_a[0]).length()*9+conv<vec_ZZ>(s_a[1]).length()*9 << "\n";
		// // cout << " +     r_b : " << r_a.length()*8 << "\n";
		// cout << " +      m2 : " << m2_a.length()*16 << "\n";
		// cout << "Total bits : " << Ke_a.length()*16+conv<vec_ZZ>(s_a[0]).length()*9+conv<vec_ZZ>(s_a[1]).length()*9+m2_a.length()*16 << "\n";


		

	}	
	return 0;
}
