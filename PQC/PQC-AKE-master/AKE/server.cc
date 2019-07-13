#include "helpers.cc"


#define BACKLOG 10
using namespace std;
using namespace NTL;
using json = nlohmann::json;
int retries = 0;

#define bufSize 1024*32
//SERVER IS BOB
//Run as ./server 8080



int main(int argc, char* argv[]){
	srand(rdtsc());
	clock_t t1,t2;
	float tb_ds_keygen, tb_ds_ver, tb_kem_enc, tb_h2, tb_ds_sig, tb_h1, tb_total1, tb_total2;
	unsigned long long c1,c2;
 	long long cb_ds_keygen, cb_ds_ver, cb_kem_enc, cb_h2, cb_ds_sig, cb_h1, cb_total1, cb_total2;


	//Bob Generate SigKeyGen (Previous to actual AKE Exchange)
	ZZX 	Ks_b[2];
	ZZ_pX 	Kv_a , Kv_b;

	MSK_Data * MSKD_b = new MSK_Data;													//Bob:   (Ks2,Ks2) <- SigKeyGen

	// t1 = clock();
	// c1 = cpucycles();
	SigKeyGen(Ks_b,Kv_b,MSKD_b);														//BOB:   sk(2) <- BOT
	// c2 = cpucycles();	
	// t2 = clock();
	// cb_ds_keygen = c2-c1;
	// tb_ds_keygen = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

	sockaddr_in my_addr;
	int sockfd,x;
	unsigned int sin_size;
	
	my_addr.sin_family = AF_INET; // host byte order
	my_addr.sin_port = htons(atoi(argv[1]));
	inet_aton("127.0.0.1",(in_addr*)&(my_addr.sin_addr));
	memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct
	
	sockfd = socket (PF_INET, SOCK_STREAM, 0); 
	
	bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
	if(x==-1)	{
		cout<<"Binding unsuccessful."<<endl;
		return 0;
	}
	cout<<"Successfully Binded."<<endl;	

	listen(sockfd, BACKLOG);
	cout<<"Server is Listening..."<<endl;
	sin_size = sizeof(struct sockaddr_in);

	int pid,newf,counter=0	;
	char welcome[bufSize];

	unsigned char keyArray[32];
	bool skSet = false;
	unsigned char ivArray[AES::BLOCKSIZE];

	json j;
	stringstream temp;
	temp << Kv_b;
	j["Kv_b"] = temp.str();
	j["STATE"] = "CONNECT";

	while(true)	{
		newf = accept(sockfd, (struct sockaddr *)&my_addr, &sin_size); //always accepting
		string jDump = j.dump();
		// send(newf, welcome, bufSize, 0);
		send(newf,jDump.c_str(),jDump.length()+1,0);
		cout<<"Connected to new client socket number "<<sockfd<<endl;
        if ((pid = fork()) == -1)	{
            close(newf);
            continue;
        } 	
        else if(pid > 0)	{
            close(newf);
            counter++;
            continue;
        }
        else if(pid == 0)	{
            char receive[bufSize];
            char reply[bufSize];
            counter++;
            
			json jsonSend;
			json jsonReceive;
			string state = "NULL";
			string jDump;

            while(true)	{
				recv(newf, receive, bufSize, 0);
				if(receive[0] == '\0'){
					// cout << "received nothing?\n";
					continue;
				}
				cout<<"Message from "<<sockfd<<" and client"<<counter<<" : ";
				if(skSet){
					string receiveString(receive);
					// cout << "\ncipher text: " << receiveString << "\n";
					jsonReceive = json::parse(decryptString(*keyArray, receiveString, ivArray));
				}
				else{
					jsonReceive = json::parse(receive);
				}
				state = jsonReceive.value("STATE", "NULL");
				jsonSend.clear(); //empty the jsonSend

				if(state=="NULL"){
					cout << "NO STATE OR STATE == \"NULL\"\n";
					continue;
				}

				else if(state=="SIGMA1"){
					//deserializing the json
					cout << "SIGMA1\n";
					string Kv_a_str, m2_a_str, s_a_0_str, s_a_1_str, ivString;
					// unsigned char tempArray[AES::BLOCKSIZE];
					Kv_a_str = jsonReceive.value("Kv_a", "NULL"); //should have been gotten beforehand...
					m2_a_str = jsonReceive.value("m2_a", "NULL");
					s_a_0_str = jsonReceive.value("s_a[0]", "NULL");
					s_a_1_str = jsonReceive.value("s_a[1]", "NULL");
					ivString = jsonReceive.value("IV","NULL");
					size_t pos = 0;
					string token;
					string delimiter = ",";
					int index=0;
					int temp;
					while ((pos = ivString.find(delimiter)) != string::npos) {
						token = ivString.substr(0, pos);
						sscanf(token.c_str(), "%d", &temp);
						ivArray[index] = (unsigned char) temp;
						ivString.erase(0, pos + delimiter.length());
						index+=1;
					}
					vec_ZZ Ke_a;
					ZZ_pX Kv_a;
					vec_ZZ m2_a;
					ZZX s_a[2];

					ZZX zzx_temp;

					zzx_temp = stringToZZX(Kv_a_str);
					Kv_a = conv<ZZ_pX>(zzx_temp);

					zzx_temp = stringToZZX(m2_a_str);
					m2_a = conv<vec_ZZ>(zzx_temp);

					zzx_temp = stringToZZX(s_a_0_str);
					s_a[0] = conv<ZZX>(zzx_temp);
					zzx_temp = stringToZZX(s_a_1_str);
					s_a[1] = conv<ZZX>(zzx_temp);

					

					//Bob
					ZZX Ke_a_temp;
					vec_ZZ sk_b;
					ZZX c_b,k_b; 
					vec_ZZ Auth_b;
					ZZX s_b[2];	
					vec_ZZ r_b; 
					vec_ZZ c_Auth;
					vec_ZZ m1_a;
					vec_ZZ m2_b;
					//cout << Kv_a;
						// t1 = clock();
						// c1 = cpucycles();
					//TODO
					if ( Verify2(conv<ZZX>(Kv_a),s_a,m2_a,m1_a) ){										//BOB: if (Ver(Kv1,simga1) != BOT) Then
							// c2 = cpucycles();
							// t2 = clock();
							// cb_ds_ver = c2-c1;
							// tb_ds_ver = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;
						Ke_a = m1_a;
						Ke_a.append(m2_a);
						Ke_a_temp = conv<ZZX>(Ke_a);

							// t1 = clock();
							// c1 = cpucycles();
						Encapsulate(Ke_a_temp,c_b,k_b);													//BOB: (c,k) <- Enc(Ke)
							// c2 = cpucycles();
							// t2 = clock();
							// cb_kem_enc = c2-c1;
							// tb_kem_enc = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

							// t1 = clock();
							// c1 = cpucycles();
						Hash2(Auth_b, Ke_a, conv<vec_ZZ>(c_b), conv<vec_ZZ>(k_b));						//BOB: Auth  <- H2(sigma1,c,k)
							// c2 = cpucycles();
							// t2 = clock();
							// cb_h2 = c2-c1;
							// tb_h2 = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

						
						c_Auth = Auth_b;
						c_Auth.append(conv<vec_ZZ>(c_b));

						// cout << "c_b: " << c_b << "\n\n";						
						
							// t1 = clock();
							// c1 = cpucycles();
						//TODO
						Sign2(s_b, m2_b,c_Auth, MSKD_b);	//Ks_a == MSKD_a which contains f,g 													//BOB: Sigma2 <- Sig(Ks2,(c,k))
														//s1 => renamed as s2 will be inside s_a[1]


							// c2 = cpucycles();
							// t2 = clock();
							// cb_ds_sig = c2-c1;
							// tb_ds_sig = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

							// t1 = clock();
							// c1 = cpucycles();
						Hash1(sk_b, Ke_a, c_Auth, conv<vec_ZZ>(k_b));
							// c2 = cpucycles();
							// t2 = clock();
							// cb_h1 = c2-c1;
							// tb_h1 = ((float)t2 - (float)t1)/CLOCKS_PER_SEC * 1000;

						
						// cout <<"sk_b length: "<<sk_b.length() <<"\n";
					}
					else{ cout << "Bob: Abort!\n"; }
								int convInt;
				for(int i=0;i<sk_b.length();i++){
					convInt = conv<int>(sk_b[i]);
					keyArray[i] = (unsigned char) convInt;
					// sprintf(&hexChar[i*2], "%02X", temp);
				}
				skSet = true;
				//Bob sends Sigma2 to Alice
					// Aka. Alice has access to:
					// c_Auth ] 
					// s1_b   ] -- Sent from Bob
					// r_b    ]
					// Kv_b   ] -- (Public Obtained before hand).
					// cout << "\nTransmitting (B->A)\n";
					// cout << " +  c_auth : " << c_Auth.length()*16 << "\n";
					// cout << " +      s1 : " << conv<vec_ZZ>(s_b[1]).length()*9 << "\n";
					// // cout << " +     r_b : " << r_b.length()*8 << "\n";
					// cout << "Total bits : " <<conv<vec_ZZ>(s_b[1]).length()*9+c_Auth.length()*16 << "\n";

					jsonSend = sigmaTwoJson(s_b,m2_b);
					jDump = jsonSend.dump(); //serialize the json
					cout << "SENDING SIGMA2\n";
					send(newf,jDump.c_str(),jDump.length()+1,0);
					delete MSKD_b; MSKD_b = NULL;

				}
				else if(state=="DATA"){
					cout << "DATA: ";
					cout << jsonReceive.value("DATA", "NULL") << "\n";
					continue;
				}

				memset(receive, 0, sizeof receive);

				send(newf, receive, bufSize, 0);
				// 	close(newf);
				// 	break;
				// }	
				// for(int i=0;i<bufSize;i++)	{
				// 	reply[i]=toupper(buffer[i]);
				// }	
				// cout<<"Replied to "<<sockfd<<" and client"<<counter<<" : "<<reply<<endl;
				// send(newf, reply, bufSize, 0);	
			}
            
            close(newf);
            break;
		}
	}
}
