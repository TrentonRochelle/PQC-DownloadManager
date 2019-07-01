#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/mat_ZZ.h>
#include <gmp.h>

#include "Random.h"
#include "params.h"

using namespace std;
using namespace NTL;


vec_ZZ RandomVector()
{
    vec_ZZ w;
    unsigned int i;
    w.SetLength(N0);
    for(i=0; i<N0; i++)
    {
        w[i] = conv<ZZ>(rand())%q1;
    }
    return w;
}


//==============================================================================
//Generates a random polynomial of fixed degree
//==============================================================================
ZZX RandomPoly(const unsigned int degree)
{
    unsigned int i;
    ZZX f;
    f.SetLength(degree+1);
    for(i=0; i<=degree; i++)
    {
        f[i] = rand();
    }
    return f;
}


//==============================================================================
//Generates a random polynomial of fixed degree and "approximately" fixed squared norm
//==============================================================================
ZZX RandomPolyFixedSqNorm(const ZZ& SqNorm, const unsigned int degree)
{
    unsigned int i;
    ZZ SqNorm0, Ratio;
    ZZX f;
    f.SetLength(degree+1);

    RR_t sigma = sqrt( ( (double) conv<double>(SqNorm)/(degree+1) ) );

    for(i=0; i<=degree; i++)
    {
        f[i] = conv<ZZ>(Sample3(sigma));
    }
    f[degree] |= 1;
    //f[degree]=conv<ZZ>(3);
    return f;
}

//==============================================================================
//Generates a random polynomial of fixed degree and "approximately" fixed squared norm and f(1)=1
//==============================================================================
ZZX RandomPolyFixedSqNorm2(const ZZ& SqNorm, const unsigned int degree)
{
    unsigned int i;
    ZZ SqNorm0, Ratio;
    ZZX f;
    f.SetLength(degree+1);

    RR_t sigma = sqrt( ( (double) conv<double>(SqNorm)/(degree+1) ) );
    ZZ sum = conv<ZZ>(0);
    for(i=0; i<=degree-1; i++)
    {
        f[i] = conv<ZZ>(Sample3(sigma));
        sum += f[i];
    }
    f[degree]=(1-sum)%q0;
    //f[degree] |= 1;
    return f;
}

//==============================================================================
//Generates a random alphanumeric string of fixed size.
//==============================================================================
void RandomString(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

