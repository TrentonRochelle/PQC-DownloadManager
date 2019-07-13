PREFIX=$(HOME)
CC=g++
AR=ar


#Run as "make clean" and then "make all"

# Case 1: These are the standard compilation flags CCFLAGS and linker flags LDFLAGS.
CCFLAGS= -std=gnu++0x -Ofast -mavx2 -mavx -mpclmul -I/usr/include/crypto++
LDFLAGS= -lntl -lgmp -lcrypto -L/usr/lib/crypto++ -lcrypto++

# Case 2: If NTL is installed in a specific location, say /path/to/ntl, you must specify it by using the CCFLAGS and LDFLAGS below instead.
# CCFLAGS= -Wall -I/path/to/ntl/include/ -std=gnu++0x -Ofast 
# LDFLAGS= -L/path/to/ntl/lib/ -lntl -lgmp 

# Case 3: In some cases, Unix doesn't find NTL even if it is installed in the standard location /usr/local. Then, uncomment the following lines.
# CCFLAGS= -Wall -I/usr/local/include/ -std=gnu++0x -Ofast 
# LDFLAGS= -L/usr/local/lib/ -lntl -lgmp 
AKE_SRC := AKE.cc
CLIENT_SRC := client.cc
SERVER_SRC := server.cc
HELPER_SRC := helpers.cc
SRCS=$(filter-out $(AKE_SRC) $(CLIENT_SRC) $(SERVER_SRC) $(HELPER_SRC),$(wildcard *.cc))
OBJS=$(SRCS:.cc=.o)
AKE_OBJ=$(AKE_SRC:.cc=.o)
CLIENT_OBJ=$(CLIENT_SRC:.cc=.o)
SERVER_OBJ=$(SERVER_SRC:.cc=.o)
.PHONY: all clean mrproper

all: client server

AKE: $(OBJS) $(AKE_OBJ)
	$(CC) $(CCFLAGS) AKE.cc -o AKE $(OBJS) $(LDFLAGS)

client: $(OBJS) $(SERVER_OBJ)
	$(CC) $(CCFLAGS) client.cc -o client $(OBJS) $(LDFLAGS)

server: $(OBJS) $(CLIENT_OBJ)
	$(CC) $(CCFLAGS) server.cc -o server $(OBJS) $(LDFLAGS)

%.o: %.cc params.h
	$(CC) $(CCFLAGS) -c $< 

clean:
	rm -f client.o
	rm -f server.o
	rm -f AKE.o

cleanall:
	rm -f *.o

mrproper:
	rm -f AKE