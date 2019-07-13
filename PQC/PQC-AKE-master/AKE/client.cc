#include "helpers.cc"



int retries = 0;



#define BACKLOG 10 // how many pending connections queue will hold
#define bufSize 1024*32 //32kB
//CLIENT IS ALICE



int main(int argc, char* argv[])	{
	CryptoPP::AutoSeededRandomPool prng;
	srand(rdtsc());



	//PQC SETUP
	clock_t t1,t2;
	float ta_ds_keygen, ta_kem_keygen, ta_ds_sig, ta_ds_ver, ta_kem_dec, ta_h2, ta_h1, ta_total1, ta_total2;
	unsigned long long c1,c2;
 	long long ca_ds_keygen, ca_kem_keygen, ca_ds_sig, ca_ds_ver, ca_kem_dec, ca_h2, ca_h1, ca_total1, ca_total2;


	//Alice and Bob Generate SigKeyGen (Previous to actual AKE Exchange)
	ZZX 	Ks_a[2];
	ZZ_pX 	Kv_a , Kv_b;

	MSK_Data * MSKD_a = new MSK_Data;													//ALice: (Ks1,Kv1) <- SigKeyGen

	// t1 = clock();
	// c1 = cpucycles();
	SigKeyGen(Ks_a,Kv_a,MSKD_a);														//ALICE: sk(1) <- BOT
	// c2 = cpucycles();
	// t2 = clock();
	// ca_ds_keygen = c2-c1;
	// ta_ds_keygen = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
		
	//Alice
	vec_ZZ sk_a;
	ZZX Kd_a, Ke_a_temp, Kd_inv2_a;

		// t1 = clock();
		// c1 = cpucycles();
	KEMKeyGen(Kd_a,Ke_a_temp, Kd_inv2_a);															//ALICE: (Kd,Ke) <- KEMKeyGen
		// c2 = cpucycles();
		// t2 = clock();
		// ca_kem_keygen = c2-c1;
		// ta_kem_keygen = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
	vec_ZZ Ke_a = conv<vec_ZZ>(Ke_a_temp); //public key for alice

	vec_ZZ r_a;
	ZZX s_a[2];
	vec_ZZ m2_a;

	// t1 = clock();
	// c1 = cpucycles();
	//TODO
	Sign2(s_a,m2_a,Ke_a,MSKD_a); //Ks_a == MSKD_a which contains f,g 						//ALICE: simga1 <- Sig(Ks1,Ke)
								//s1 => renamed as s2 will be inside s_a[1]

	// c2 = cpucycles();
	// t2 = clock();
	// ca_ds_sig = c2-c1;
	// ta_ds_sig = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

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
	bool skSet=false; //boolean to check if sk_a and sk_b are the same
	unsigned char keyArray[32];

	unsigned char ivArray[AES::BLOCKSIZE];
	prng.GenerateBlock(ivArray, sizeof(ivArray));

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
		cout<<"Server Message : ";
		if(skSet){
			string receiveString(receive);
			jsonReceive = json::parse(decryptString(*keyArray, receiveString, ivArray));
		}
		else{
			jsonReceive = json::parse(receive);
		}
		state = jsonReceive.value("STATE", "NULL");
		
		if(state=="CONNECT"){
			cout << "CONNECT\n";
			Kv_b = conv<ZZ_pX>(stringToZZX(jsonReceive.value("Kv_b", "NULL")));
			jsonSend = sigmaOneJson(Kv_a, m2_a, s_a); //Kv_a should be gotten beforehand...
			string ivString;
			int temp;
			for(int i=0;i<AES::BLOCKSIZE;i++){
				temp = (int) ivArray[i];
				ivString += (to_string(temp) + ",");
			}
			jsonSend["IV"] = ivString;
			cout << "ivArray: " << ivArray << "\n";
			jDump = jsonSend.dump(); //serialize the json
			cout << "SENDING SIGMA1\n";
			send(sockfd,jDump.c_str(),jDump.length()+1,0);
			continue;

		}
		else if(state=="SIGMA2"){
			cout << "SIGMA2\n";

			string m2_b_str, s_b_0_str, s_b_1_str;
			m2_b_str = jsonReceive.value("m2_b", "NULL");
			s_b_0_str = jsonReceive.value("s_b[0]", "NULL");
			s_b_1_str = jsonReceive.value("s_b[1]", "NULL");

			vec_ZZ m2_b;
			ZZX s_b[2];

			ZZX zzx_temp;

			zzx_temp = stringToZZX(m2_b_str);
			m2_b = conv<vec_ZZ>(zzx_temp);

			zzx_temp = stringToZZX(s_b_0_str);
			s_b[0] = conv<ZZX>(zzx_temp);
			zzx_temp = stringToZZX(s_b_1_str);
			s_b[1] = conv<ZZX>(zzx_temp);

			ZZX c_b;
			c_b.SetLength(N0);
			
			//Alice
			vec_ZZ c_Auth;
			
			// t1 = clock();
			// c1 = cpucycles();

			vec_ZZ m1_b;
			if ( Verify2(conv<ZZX>(Kv_b),s_b,m2_b,m1_b) ){
					// c2 = cpucycles();
					// t2 = clock();
					// ca_ds_ver = c2-c1;
					// ta_ds_ver = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
				c_Auth = m1_b; //last 512 values are c_b
				c_Auth.append(m2_b);

			int length = m1_b.length(); //544

			for(int i=0;i<N0;i++){//0-511
				c_b[i] = m1_b[i+length-N0];
			}
			vec_ZZ Auth_b;
			Auth_b.SetLength(32);
			for(int i=0;i<32;i++){
				Auth_b[i] = m1_b[i];
			}

				ZZX k_a;
				
					// t1 = clock();
					// c1 = cpucycles();
				Decapsulate(Kd_a,c_b,k_a, Kd_inv2_a);
					// c2 = cpucycles();
					// t2 = clock();
					// ca_kem_dec = c2-c1;
					// ta_kem_dec = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

				vec_ZZ Auth_a;
				
					// t1 = clock();
					// c1 = cpucycles();
				Hash2(Auth_a, Ke_a, conv<vec_ZZ>(c_b), conv<vec_ZZ>(k_a));
					// c2 = cpucycles();
					// t2 = clock();
					// ca_h2 = c2-c1;
					// ta_h2 = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

				if (IsZero(Auth_a - Auth_b)){

						// t1 = clock();
						// c1 = cpucycles();
					// Hash1(sk_a, Ke_a, c_Auth, conv<vec_ZZ>(k_b));
					Hash1(sk_a, Ke_a, c_Auth, conv<vec_ZZ>(k_a)); //I think it should be k_a according to the PDF. This code is off the goop
						// c2 = cpucycles();
						// t2 = clock();
						// ca_h1 = c2-c1;
						// ta_h1 = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

					//cout <<"SK_a = "<<sk_a <<"\n";

				}
				else{cout << "Alice: Abort! (H2 Hashes Didn't Match!)"; }
				

			}
			else{ cout << "Alice: Abort!";}	

			//CHECK IF EVERYTHING WORKED!
			// cout << "sk_a:" << sk_a << "\n";
			// if (IsZero(sk_a - sk_b)){
			// 	cout << "\nsk_a == sk_b; Successful AKE!\n";
			// }
			// char hexChar[sk_a.length()*2 + 1];
			int convInt;
			for(int i=0;i<sk_a.length();i++){
				convInt = conv<int>(sk_a[i]);
				keyArray[i] = (unsigned char) convInt;
				// sprintf(&hexChar[i*2], "%02X", temp);
			}
			// string keyString(hexChar);
			skSet = true;




			// Only you can prevent memory leaks!
			delete MSKD_a; MSKD_a = NULL;
			jsonSend.clear();
			jsonSend["STATE"] = "DATA";
			jsonSend["DATA"] = "TEST ENCRYPTION";
			jDump = jsonSend.dump(); //serialize the json

			string cipher, encoded;
			
			try
			{
				cout << "jDump: " << jDump << endl;
				
				CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
				e.SetKeyWithIV( keyArray, 32 ,ivArray);
				
				cipher = encryptString(jDump, e);
				
			}
			catch( CryptoPP::Exception& e )
			{
				cerr << e.what() << endl;
				exit(1);
			}
			// CryptoPP::StringSource( cipher, true,
			// 	new CryptoPP::HexEncoder(
			// 		new CryptoPP::StringSink( encoded )
			// 	) // HexEncoder
			// ); 
			// cout << "encoded text: " << encoded << endl;
			// cout << "cipher text: " << cipher << endl;
			// cout << "decrypted: " << decrypt(*keyArray, cipher) << endl;


			cout << "SENDING DATA\n";
			send(sockfd,cipher.c_str(),cipher.length()+1,0);
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
