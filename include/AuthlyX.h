// AuthlyX SDK Version 2.1
#pragma once

#if !defined(__cplusplus)
#include <stddef.h>
#endif

#ifdef __cplusplus

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <shlobj.h>
#include <ctime>
#include <cmath>
#include <chrono>
#include <regex>
#include <algorithm>
#include <memory>
#include <cctype>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <wincrypt.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

namespace AuthlyXTweetNaCl {
#define FOR(i,n) for (i = 0;i < n;++i)
#define sv static void

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];
static void randombytes(u8 *,u64) {}

static const u8
  _0[16] = {0},
  _9[32] = {9};
static const gf
  gf0 = {0},
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u32 L32(u32 x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

static u32 ld32(const u8 *x)
{
  u32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

static u64 dl64(const u8 *x)
{
  u64 i,u=0;
  FOR(i,8) u=(u<<8)|x[i];
  return u;
}

sv st32(u8 *x,u32 u)
{
  int i;
  FOR(i,4) { x[i] = u; u >>= 8; }
}

sv ts64(u8 *x,u64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static int vn(const u8 *x,const u8 *y,int n)
{
  u32 i,d = 0;
  FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

int crypto_verify_16(const u8 *x,const u8 *y)
{
  return vn(x,y,16);
}

int crypto_verify_32(const u8 *x,const u8 *y)
{
  return vn(x,y,32);
}

sv core(u8 *out,const u8 *in,const u8 *k,const u8 *c,int h)
{
  u32 w[16],x[16],y[16],t[4];
  int i,j,m;

  FOR(i,4) {
    x[5*i] = ld32(c+4*i);
    x[1+i] = ld32(k+4*i);
    x[6+i] = ld32(in+4*i);
    x[11+i] = ld32(k+16+4*i);
  }

  FOR(i,16) y[i] = x[i];

  FOR(i,20) {
    FOR(j,4) {
      FOR(m,4) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1],13);
      t[0] ^= L32(t[3]+t[2],18);
      FOR(m,4) w[4*j+(j+m)%4] = t[m];
    }
    FOR(m,16) x[m] = w[m];
  }

  if (h) {
    FOR(i,16) x[i] += y[i];
    FOR(i,4) {
      x[5*i] -= ld32(c+4*i);
      x[6+i] -= ld32(in+4*i);
    }
    FOR(i,4) {
      st32(out+4*i,x[5*i]);
      st32(out+16+4*i,x[6+i]);
    }
  } else
    FOR(i,16) st32(out + 4 * i,x[i] + y[i]);
}

int crypto_core_salsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c)
{
  core(out,in,k,c,0);
  return 0;
}

int crypto_core_hsalsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c)
{
  core(out,in,k,c,1);
  return 0;
}

static const u8 sigma[16] = {'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'};

int crypto_stream_salsa20_xor(u8 *c,const u8 *m,u64 b,const u8 *n,const u8 *k)
{
  u8 z[16],x[64];
  u32 u,i;
  if (!b) return 0;
  FOR(i,16) z[i] = 0;
  FOR(i,8) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,64) c[i] = (m?m[i]:0) ^ x[i];
    u = 1;
    for (i = 8;i < 16;++i) {
      u += (u32) z[i];
      z[i] = u;
      u >>= 8;
    }
    b -= 64;
    c += 64;
    if (m) m += 64;
  }
  if (b) {
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,b) c[i] = (m?m[i]:0) ^ x[i];
  }
  return 0;
}

int crypto_stream_salsa20(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  return crypto_stream_salsa20_xor(c,0,d,n,k);
}

int crypto_stream(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  u8 s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,d,n+16,s);
}

int crypto_stream_xor(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  u8 s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,n+16,s);
}

sv add1305(u32 *h,const u32 *c)
{
  u32 j,u = 0;
  FOR(j,17) {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

static const u32 minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

int crypto_onetimeauth(u8 *out,const u8 *m,u64 n,const u8 *k)
{
  u32 s,i,j,u,x[17],r[17],h[17],c[17],g[17];

  FOR(j,17) r[j]=h[j]=0;
  FOR(j,16) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    FOR(j,17) c[j] = 0;
    for (j = 0;(j < 16) && (j < n);++j) c[j] = m[j];
    c[j] = 1;
    m += j; n -= j;
    add1305(h,c);
    FOR(i,17) {
      x[i] = 0;
      FOR(j,17) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }
    FOR(i,17) h[i] = x[i];
    u = 0;
    FOR(j,16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >> 2);
    FOR(j,16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  FOR(j,17) g[j] = h[j];
  add1305(h,minusp);
  s = 0u - (h[16] >> 7);
  FOR(j,17) h[j] ^= s & (g[j] ^ h[j]);

  FOR(j,16) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  FOR(j,16) out[j] = h[j];
  return 0;
}

int crypto_onetimeauth_verify(const u8 *h,const u8 *m,u64 n,const u8 *k)
{
  u8 x[16];
  crypto_onetimeauth(x,m,n,k);
  return crypto_verify_16(h,x);
}

int crypto_secretbox(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  int i;
  if (d < 32) return -1;
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c + 16,c + 32,d - 32,c);
  FOR(i,16) c[i] = 0;
  return 0;
}

int crypto_secretbox_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k)
{
  int i;
  u8 x[32];
  if (d < 32) return -1;
  crypto_stream(x,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,d - 32,x) != 0) return -1;
  crypto_stream_xor(m,c,d,n,k);
  FOR(i,32) m[i] = 0;
  return 0;
}

sv set25519(gf r, const gf a)
{
  int i;
  FOR(i,16) r[i]=a[i];
}

sv car25519(gf o)
{
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static u8 par25519(const gf a)
{
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

sv unpack25519(gf o, const u8 *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

sv A(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

sv Z(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

sv M(gf o,const gf a,const gf b)
{
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

sv S(gf o,const gf a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

sv pow2523(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

int crypto_scalarmult(u8 *q,const u8 *n,const u8 *p)
{
  u8 z[32];
  i64 x[80],r,i;
  gf a,b,c,d,e,f;
  FOR(i,31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  FOR(i,16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  FOR(i,16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

int crypto_scalarmult_base(u8 *q,const u8 *n)
{
  return crypto_scalarmult(q,n,_9);
}

int crypto_box_keypair(u8 *y,u8 *x)
{
  randombytes(x,32);
  return crypto_scalarmult_base(y,x);
}

int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x)
{
  u8 s[32];
  crypto_scalarmult(s,x,y);
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

int crypto_box_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  return crypto_secretbox(c,m,d,n,k);
}

int crypto_box_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k)
{
  return crypto_secretbox_open(m,c,d,n,k);
}

int crypto_box(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x)
{
  u8 k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_afternm(c,m,d,n,k);
}

int crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x)
{
  u8 k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_open_afternm(m,c,d,n,k);
}

static u64 R(u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static u64 Ch(u64 x,u64 y,u64 z) { return (x & y) ^ (~x & z); }
static u64 Maj(u64 x,u64 y,u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static u64 Sigma0(u64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
static u64 Sigma1(u64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
static u64 sigma0(u64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
static u64 sigma1(u64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

static const u64 K[80] =
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

int crypto_hashblocks(u8 *x,const u8 *m,u64 n)
{
  u64 z[8],b[8],a[8],w[16],t;
  int i,j;

  FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);

  while (n >= 128) {
    FOR(i,16) w[i] = dl64(m + 8 * i);

    FOR(i,80) {
      FOR(j,8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	FOR(j,16)
	  w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  FOR(i,8) ts64(x+8*i,z[i]);

  return n;
}

static const u8 iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

int crypto_hash(u8 *out,const u8 *m,u64 n)
{
  u8 h[64],x[256];
  u64 i,b = n;

  FOR(i,64) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;

  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  FOR(i,64) out[i] = h[i];

  return 0;
}

sv add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

sv cswap(gf p[4],gf q[4],u8 b)
{
  int i;
  FOR(i,4)
    sel25519(p[i],q[i],b);
}

sv pack(u8 *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

sv scalarmult(gf p[4],gf q[4],const u8 *s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

sv scalarbase(gf p[4],const u8 *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

int crypto_sign_keypair(u8 *pk, u8 *sk)
{
  u8 d[64];
  gf p[4];
  int i;

  randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d);
  pack(pk,p);

  FOR(i,32) sk[32 + i] = pk[i];
  return 0;
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

sv modL(u8 *r,i64 x[64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

sv reduce(u8 *r)
{
  i64 x[64],i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk)
{
  u8 d[64],h[64],r[64];
  i64 i,j,x[64];
  gf p[4];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = n+64;
  FOR(i,n) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  FOR(i,32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);

  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);

  return 0;
}

static int unpackneg(gf r[4],const u8 p[32])
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

int crypto_sign_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk)
{
  int i;
  u8 t[32],h[64];
  gf p[4],q[4];

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

}

#undef FOR
#undef sv

namespace Ed25519 {
inline bool VerifyDetached(const unsigned char* signature, const unsigned char* message, size_t messageLength, const unsigned char* publicKey) {
    if (!signature || !message || !publicKey) {
        return false;
    }

    std::vector<unsigned char> signedMessage(64 + messageLength);
    std::memcpy(signedMessage.data(), signature, 64);
    if (messageLength > 0) {
        std::memcpy(signedMessage.data() + 64, message, messageLength);
    }

    std::vector<unsigned char> openedMessage(signedMessage.size());
    AuthlyXTweetNaCl::u64 openedLength = 0;
    if (AuthlyXTweetNaCl::crypto_sign_open(openedMessage.data(), &openedLength, signedMessage.data(), static_cast<AuthlyXTweetNaCl::u64>(signedMessage.size()), publicKey) != 0) {
        return false;
    }

    return openedLength == static_cast<AuthlyXTweetNaCl::u64>(messageLength);
}
}

class AuthlyLogger {
public:
    static bool Enabled;
    static std::string AppName;

    static void Log(const std::string& content) {
        if (!Enabled) return;

        try {
            char commonAppData[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, commonAppData))) {
                std::string rootDir = std::string(commonAppData) + "\\AuthlyX";
                std::string baseDir = rootDir + "\\" + (AppName.empty() ? "default" : AppName);

                CreateDirectoryA(rootDir.c_str(), NULL);
                CreateDirectoryA(baseDir.c_str(), NULL);

                std::string logFile = baseDir + "\\" + GetCurrentDate() + ".log";
                std::string redacted = Redact(content);

                std::ofstream file(logFile, std::ios::app);
                if (file) {
                    file << "[" << GetCurrentTime() << "] " << redacted << std::endl;
                }
            }
        }
        catch (...) {}
    }

private:
    static std::string GetCurrentDate() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[32];
        sprintf_s(buffer, sizeof(buffer), "%04d_%02d_%02d", st.wYear, st.wMonth, st.wDay);
        return buffer;
    }

    static std::string GetCurrentTime() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[32];
        sprintf_s(buffer, sizeof(buffer), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }

    static std::string Redact(const std::string& text) {
        if (text.empty()) return text;

        std::string result = text;
        const std::vector<std::string> fields = {
            "session_id", "owner_id", "secret", "password", "key", "license_key", "hash",
            "request_id", "nonce", "hwid", "sid", "x-v2-signature", "x-auth-signature"
        };

        for (const auto& field : fields) {
            std::regex jsonQuoted("\"" + field + "\"\\s*:\\s*\"([^\"]*)\"", std::regex_constants::icase);
            result = std::regex_replace(result, jsonQuoted, "\"" + field + "\":\"***\"");

            std::regex jsonBare("\"" + field + "\"\\s*:\\s*([^,}\\s]+)", std::regex_constants::icase);
            result = std::regex_replace(result, jsonBare, "\"" + field + "\":\"***\"");

            std::regex headerPattern("(" + field + "\\s*:\\s*)([^\\r\\n]+)", std::regex_constants::icase);
            result = std::regex_replace(result, headerPattern, "$1***");
        }

        return result;
    }
};

inline bool AuthlyLogger::Enabled = false;
inline std::string AuthlyLogger::AppName = "AuthlyX";

class AuthlyX {
private:
    static constexpr const char* DefaultBaseUrl = "https://authly.cc/api/v2";
    static constexpr const char* DefaultServerPublicKeyDerBase64 = "MCowBQYDK2VwAyEAgX5lXPhkadeQozyudzTxDXopdJxYexD5qZ0yEq9UOMU=";
    std::string baseUrl = DefaultBaseUrl;
    std::string sessionId;
    std::string ownerId;
    std::string appName;
    std::string version;
    std::string secret;
    std::string applicationHash;
    bool initialized = false;
    std::string serverPublicKeyPem;
    bool requireSignedResponses = false;
    long long allowedClockSkewMs = 300000;
    std::string cachedPublicIp;
    long long cachedPublicIpExpiresAt = 0;

public:
    struct Response {
        bool success = false;
        std::string message;
        std::string raw;
        std::string code;
        int statusCode = 0;
        std::string requestId;
        std::string nonce;
        std::string signatureKid;
    };

    struct UserData {
        std::string username;
        std::string email;
        std::string licenseKey;
        std::string subscription;
        std::string subscriptionLevel;
        std::string expiryDate;
        int daysLeft = 0;
        std::string lastLogin;
        std::string hwid;
        std::string ipAddress;
        std::string registeredAt;
    };

    struct VariableData {
        std::string varKey;
        std::string varValue;
        std::string updatedAt;
    };

    struct UpdateData {
        bool available = false;
        std::string latestVersion;
        std::string downloadUrl;
        bool autoUpdateEnabled = false;
        bool forceUpdate = false;
        std::string changelog;
        bool showReminder = false;
        std::string reminderMessage;
        std::string allowedUntil;
    };

    struct ChatMessage {
        int id = 0;
        std::string username;
        std::string message;
        std::string createdAt;
    };

    struct ChatMessages {
        std::string channelName;
        std::vector<ChatMessage> messages;
        int count = 0;
        std::string nextCursor;
        bool hasMore = false;
    };

    Response response;
    UserData userData;
    VariableData variableData;
    UpdateData updateData;
    ChatMessages chatMessages;

    AuthlyX(const std::string& ownerId, const std::string& appName,
        const std::string& version, const std::string& secret, bool debug = true,
        const std::string& api = DefaultBaseUrl,
        const std::string& serverPublicKeyPem = "",
        bool requireSignedResponses = false,
        long long allowedClockSkewMs = 300000)
        : baseUrl(api.empty() ? DefaultBaseUrl : api),
        ownerId(ownerId),
        appName(appName),
        version(version),
        secret(secret),
        serverPublicKeyPem(serverPublicKeyPem.empty() ? DefaultServerPublicKeyDerBase64 : serverPublicKeyPem),
        requireSignedResponses(requireSignedResponses),
        allowedClockSkewMs(allowedClockSkewMs > 0 ? allowedClockSkewMs : 300000),
        loggingEnabled(debug) {

        if (ownerId.empty() || appName.empty() || version.empty() || secret.empty()) {
            response.success = false;
            response.message = "Invalid application credentials provided.";
            return;
        }

        AuthlyLogger::AppName = appName;
        AuthlyLogger::Enabled = debug;
        CalculateApplicationHash();
        AuthlyLogger::Log("[SDK] AuthlyX initialized for app '" + appName + "' using '" + baseUrl + "'.");
    }



    bool Init() {
        std::map<std::string, std::string> payload = {
            {"owner_id", ownerId},
            {"app_name", appName},
            {"version", version},
            {"secret", secret},
            {"hash", applicationHash}
        };

        std::string responseStr = PostJson("init", BuildJson(payload));

        if (responseStr.empty()) {
            if (response.message.empty()) {
                response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            }
            Error("Initialization failed: " + response.message);
            return false;
        }

        std::string errorCode = ExtractJsonValue(responseStr, "code");
        if (errorCode == "UPDATE_REQUIRED") {
            std::string errorMessage = ExtractJsonValue(responseStr, "message");
            LoadUpdateData(responseStr);

            if (errorMessage.empty()) {
                errorMessage = "Please update your app to the latest version.";
            }
            ShowRequiredUpdateConsole(errorMessage);

            response.success = false;
            response.message = errorMessage;
            return false;
        }
        else if (errorCode == "VERSION_MISMATCH") {
            LoadUpdateData(responseStr);
            response.success = false;
            response.message = ExtractJsonValue(responseStr, "message");
            if (response.message.empty()) {
                response.message = "Client version does not match server version.";
            }
            ShowVersionMismatchConsole(response.message);
            return false;
        }

        ParseResponse(responseStr);

        if (response.success) {
            sessionId = ExtractJsonValue(responseStr, "session_id");
            initialized = true;
            AuthlyLogger::Log("[INIT] Successfully initialized AuthlyX session");

            LoadUpdateData(responseStr);

            const bool hasNewerVersion =
                updateData.available &&
                !updateData.latestVersion.empty() &&
                CompareSemver(updateData.latestVersion, version) > 0;

            if (hasNewerVersion && HasWhitelistedUpdateMessage()) {
                ShowWhitelistedUpdatePrompt();
            }
        }
        else {
            AuthlyLogger::Log("[INIT_ERROR] " + response.message);
        }

        return response.success;
    }

    void CheckInit() {
        if (!initialized) {
            response.success = false;
            response.message = "AuthlyX is not initialized. Call Init() first.";
        }
    }

    bool Login(const std::string& username, const std::string& password) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"password", password},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("login", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Login(const std::string& identifier) {
        return LicenseLogin(identifier);
    }

    bool Login(const std::string& identifier, const std::string& password, const std::string& deviceType) {
        if (!deviceType.empty()) {
            return DeviceLogin(deviceType, identifier);
        }
        if (password.empty()) {
            return LicenseLogin(identifier);
        }
        return Login(identifier, password);
    }

    bool Register(const std::string& username, const std::string& password,
        const std::string& key, const std::string& email = "") {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"password", password},
            {"key", key},
            {"email", email},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("register", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool LicenseLogin(const std::string& licenseKey) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"license_key", licenseKey},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("licenses", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ExtendTime(const std::string& username, const std::string& licenseKey) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"license_key", licenseKey},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("extend", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ChangePassword(const std::string& oldPassword, const std::string& newPassword) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"old_password", oldPassword},
            {"new_password", newPassword}
        };

        std::string responseStr = PostJson("change-password", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool DeviceLogin(const std::string& deviceType, const std::string& deviceId) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"device_type", deviceType},
            {"device_id", deviceId},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("device-auth", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Authenticate(const std::string& identifier, const std::string& password = "", const std::string& deviceType = "") {
        return Login(identifier, password, deviceType);
    }

    std::string GetVariable(const std::string& varKey) {
        CheckInit();
        if (!initialized) return "";

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"var_key", varKey}
        };

        std::string responseStr = PostJson("variables", BuildJson(payload));
        ParseResponse(responseStr);

        return variableData.varValue;
    }

    bool SetVariable(const std::string& varKey, const std::string& varValue) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"var_key", varKey},
            {"var_value", varValue}
        };

        std::string responseStr = PostJson("variables/set", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Log(const std::string& message) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"message", message}
        };

        std::string responseStr = PostJson("logs", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ValidateSession() {
        if (!initialized || sessionId.empty()) {
            return false;
        }

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId}
        };

        std::string responseStr = PostJson("validate-session", BuildJson(payload));
        ParseResponse(responseStr);
        if (!response.success) {
            return false;
        }

        const std::string validValue = ExtractJsonValue(responseStr, "valid");
        if (validValue == "true") {
            return true;
        }
        if (validValue == "false") {
            return false;
        }

        return response.success;
    }

    void EnableLogging(bool enable) {
        loggingEnabled = enable;
        AuthlyLogger::Enabled = enable;
    }

    long long GetTimestampMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::string GenerateHex(size_t byteCount) {
        std::vector<unsigned char> bytes(byteCount);
        if (!bytes.empty()) {
            BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }

        std::ostringstream stream;
        stream << std::hex << std::setfill('0');
        for (unsigned char byte : bytes) {
            stream << std::setw(2) << static_cast<int>(byte);
        }
        return stream.str();
    }

    std::string Base64Encode(const std::vector<unsigned char>& bytes) {
        if (bytes.empty()) return "";

        DWORD length = 0;
        if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length)) {
            return "";
        }

        std::string output(length, '\0');
        if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &output[0], &length)) {
            return "";
        }

        if (!output.empty() && output.back() == '\0') {
            output.pop_back();
        }
        return output;
    }

    std::string BuildRequestSignature(const std::string& requestId, const std::string& nonce, long long timestampMs, const std::string& canonicalBody) {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectLength = 0;
        DWORD cbData = 0;
        std::vector<unsigned char> objectBuffer;
        std::vector<unsigned char> digest(32);
        std::string payload = std::to_string(timestampMs) + "\n" + requestId + "\n" + nonce + "\n" + canonicalBody + "\n" + secret;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
            return "";
        }

        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return "";
        }

        objectBuffer.resize(objectLength);
        if (BCryptCreateHash(algorithm, &hash, objectBuffer.data(), objectLength, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return "";
        }

        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(payload.data())), static_cast<ULONG>(payload.size()), 0);
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return Base64Encode(digest);
    }

    bool ParseBaseUrl(std::wstring& host, INTERNET_PORT& port, std::wstring& pathBase, bool& secure) {
        std::string normalized = baseUrl;
        while (!normalized.empty() && normalized.back() == '/') normalized.pop_back();

        secure = normalized.rfind("https://", 0) == 0;
        size_t schemeLength = secure ? 8 : 7;
        if (!(secure || normalized.rfind("http://", 0) == 0)) {
            return false;
        }

        size_t slashPos = normalized.find('/', schemeLength);
        std::string hostPort = slashPos == std::string::npos ? normalized.substr(schemeLength) : normalized.substr(schemeLength, slashPos - schemeLength);
        std::string path = slashPos == std::string::npos ? "" : normalized.substr(slashPos);

        size_t colonPos = hostPort.find(':');
        std::string hostOnly = colonPos == std::string::npos ? hostPort : hostPort.substr(0, colonPos);
        std::string portOnly = colonPos == std::string::npos ? "" : hostPort.substr(colonPos + 1);

        host = std::wstring(hostOnly.begin(), hostOnly.end());
        port = portOnly.empty()
            ? (secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT)
            : static_cast<INTERNET_PORT>(std::stoi(portOnly));
        pathBase = std::wstring(path.begin(), path.end());
        return !host.empty();
    }

    std::vector<unsigned char> Base64Decode(const std::string& input) {
        if (input.empty()) return {};

        DWORD flags = input.find("BEGIN") != std::string::npos ? CRYPT_STRING_BASE64HEADER : CRYPT_STRING_BASE64_ANY;
        DWORD outputLength = 0;
        if (!CryptStringToBinaryA(input.c_str(), 0, flags, nullptr, &outputLength, nullptr, nullptr)) {
            return {};
        }

        std::vector<unsigned char> output(outputLength);
        if (!CryptStringToBinaryA(input.c_str(), 0, flags, output.data(), &outputLength, nullptr, nullptr)) {
            return {};
        }

        output.resize(outputLength);
        return output;
    }

    std::string QueryResponseHeader(HINTERNET request, const wchar_t* headerName) {
        DWORD size = 0;
        WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, headerName, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            return "";
        }

        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, headerName, &buffer[0], &size, WINHTTP_NO_HEADER_INDEX)) {
            return "";
        }

        while (!buffer.empty() && (buffer.back() == L'\0' || buffer.back() == L'\r' || buffer.back() == L'\n')) {
            buffer.pop_back();
        }

        if (buffer.empty()) {
            return "";
        }

        int utf8Length = WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), nullptr, 0, nullptr, nullptr);
        if (utf8Length <= 0) {
            return "";
        }

        std::string value(static_cast<size_t>(utf8Length), '\0');
        WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), &value[0], utf8Length, nullptr, nullptr);
        return value;
    }

    std::string LastWinHttpErrorMessage(const std::string& fallback) {
        DWORD error = GetLastError();
        if (error == 0) {
            return fallback;
        }

        LPSTR messageBuffer = nullptr;
        DWORD length = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPSTR>(&messageBuffer),
            0,
            NULL
        );

        std::ostringstream message;
        message << fallback << " (Windows error " << error;

        if (length && messageBuffer) {
            std::string detail(messageBuffer, length);
            while (!detail.empty() && (detail.back() == '\r' || detail.back() == '\n' || detail.back() == ' ' || detail.back() == '.')) {
                detail.pop_back();
            }
            message << ": " << detail;
        }

        message << ")";

        if (messageBuffer) {
            LocalFree(messageBuffer);
        }

        return message.str();
    }

    bool VerifyEd25519Signature(const std::string& payloadToVerify, const std::string& signatureBase64) {
        if (serverPublicKeyPem.empty()) {
            return !requireSignedResponses;
        }

        std::vector<unsigned char> publicKeyBytes = Base64Decode(serverPublicKeyPem);
        std::vector<unsigned char> signatureBytes = Base64Decode(signatureBase64);
        if (publicKeyBytes.empty() || signatureBytes.size() != 64) {
            return false;
        }

        if (publicKeyBytes.size() != 32) {
            if (publicKeyBytes.size() < 32) {
                return false;
            }
            publicKeyBytes = std::vector<unsigned char>(publicKeyBytes.end() - 32, publicKeyBytes.end());
        }

        return Ed25519::VerifyDetached(
            signatureBytes.data(),
            reinterpret_cast<const unsigned char*>(payloadToVerify.data()),
            payloadToVerify.size(),
            publicKeyBytes.data());
    }

    bool ValidateResponseSecurity(
        const std::string& responseBody,
        const std::string& requestId,
        const std::string& nonce,
        HINTERNET requestHandle) {

        const std::string responseRequestId = QueryResponseHeader(requestHandle, L"x-v2-request-id");
        const std::string responseNonce = QueryResponseHeader(requestHandle, L"x-v2-nonce");
        const std::string signature = QueryResponseHeader(requestHandle, L"x-v2-signature");
        const std::string signatureTimestamp = QueryResponseHeader(requestHandle, L"x-v2-signature-ts");
        const std::string signatureKid = QueryResponseHeader(requestHandle, L"x-v2-signature-kid");

        response.requestId = requestId;
        response.nonce = nonce;
        response.signatureKid = signatureKid;

        if (!responseRequestId.empty() && responseRequestId != requestId) {
            response.success = false;
            response.code = "AUTH_REQUEST_MISMATCH";
            response.message = "Response request ID does not match the original request.";
            return false;
        }

        if (!responseNonce.empty() && responseNonce != nonce) {
            response.success = false;
            response.code = "AUTH_REQUEST_MISMATCH";
            response.message = "Response nonce does not match the original request.";
            return false;
        }

        const bool hasSignature = !signature.empty() && !signatureTimestamp.empty();
        if (!hasSignature) {
            if (requireSignedResponses) {
                response.success = false;
                response.code = "AUTH_INVALID_SIGNATURE";
                response.message = "Signed response was expected but signature headers were missing.";
                return false;
            }
            return true;
        }

        long long signatureTimestampMs = 0;
        try {
            signatureTimestampMs = std::stoll(signatureTimestamp);
        }
        catch (...) {
            response.success = false;
            response.code = "AUTH_CLOCK_OUT_OF_SYNC";
            response.message = "Response signature timestamp is invalid.";
            return false;
        }

        if (std::llabs(GetTimestampMs() - signatureTimestampMs) > allowedClockSkewMs) {
            response.success = false;
            response.code = "AUTH_CLOCK_OUT_OF_SYNC";
            response.message = "Response signature timestamp is outside the allowed clock window.";
            return false;
        }

        JsonValue root;
        if (!ParseJsonDocument(responseBody, root)) {
            response.success = false;
            response.code = "AUTH_INVALID_SIGNATURE";
            response.message = "Response body could not be parsed for signature verification.";
            return false;
        }

        const std::string canonicalBody = CanonicalizeJsonValue(root);
        const std::string payloadToVerify = signatureTimestamp + "\n" + requestId + "\n" + nonce + "\n" + canonicalBody;

        if (!VerifyEd25519Signature(payloadToVerify, signature)) {
            response.success = false;
            response.code = "AUTH_INVALID_SIGNATURE";
            response.message = "Response signature verification failed.";
            return false;
        }

        return true;
    }

    std::string PostJson(const std::string& endpoint, const std::string& jsonPayload) {
        std::wstring host;
        std::wstring pathBase;
        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        bool secure = true;
        if (!ParseBaseUrl(host, port, pathBase, secure)) {
            response.success = false;
            response.message = "Invalid API URL";
            return "";
        }

        const std::string requestId = GenerateHex(16);
        const std::string nonce = GenerateHex(16);
        const long long timestampMs = GetTimestampMs();
        const std::string requestSignature = BuildRequestSignature(requestId, nonce, timestampMs, jsonPayload);
        const std::string timestampString = std::to_string(timestampMs);

        HINTERNET hSession = WinHttpOpen(L"AuthlyX", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            response.success = false;
            response.message = LastWinHttpErrorMessage("Failed to create HTTP session");
            return "";
        }

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            std::string errorMessage = LastWinHttpErrorMessage("Failed to connect to API host");
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = errorMessage;
            return "";
        }

        std::wstring wideEndpoint = pathBase + L"/" + std::wstring(endpoint.begin(), endpoint.end());
        std::wstring wideRequestId(requestId.begin(), requestId.end());
        std::wstring wideNonce(nonce.begin(), nonce.end());
        std::wstring wideTimestamp(timestampString.begin(), timestampString.end());
        std::wstring wideSignature(requestSignature.begin(), requestSignature.end());

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wideEndpoint.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) {
            std::string errorMessage = LastWinHttpErrorMessage("Failed to create HTTP request");
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = errorMessage;
            return "";
        }

        std::wstring headers =
            L"Content-Type: application/json\r\n"
            L"Accept: application/json\r\n"
            L"x-request-id: " + wideRequestId + L"\r\n"
            L"x-v2-request-id: " + wideRequestId + L"\r\n"
            L"x-auth-nonce: " + wideNonce + L"\r\n"
            L"x-v2-nonce: " + wideNonce + L"\r\n"
            L"x-auth-timestamp: " + wideTimestamp + L"\r\n"
            L"x-v2-timestamp: " + wideTimestamp + L"\r\n"
            L"x-auth-signature: " + wideSignature + L"\r\n"
            L"x-v2-signature: " + wideSignature + L"\r\n";
        BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
            (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(),
            (DWORD)jsonPayload.length(), 0);

        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            return "";
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            return "";
        }

        std::string responseStr;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || !dwSize) break;

            std::vector<char> buffer(dwSize + 1);
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                responseStr.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX);
        response.statusCode = static_cast<int>(statusCode);

        if (!ValidateResponseSecurity(responseStr, requestId, nonce, hRequest)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return responseStr;
    }

    void CalculateApplicationHash() {
        try {
            char modulePath[MAX_PATH];
            if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) {
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;

            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::ifstream file(modulePath, std::ios::binary);
            if (!file) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            const size_t bufferSize = 8192;
            char buffer[bufferSize];

            while (file.read(buffer, bufferSize) || file.gcount() > 0) {
                if (!CryptHashData(hHash, (BYTE*)buffer, (DWORD)file.gcount(), 0)) {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, 0);
                    applicationHash = "UNKNOWN_HASH";
                    return;
                }
            }

            DWORD hashSize = 0;
            DWORD dwCount = sizeof(DWORD);
            if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &dwCount, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::vector<BYTE> hashBytes(hashSize);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::stringstream ss;
            for (DWORD i = 0; i < hashSize; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
            }
            applicationHash = ss.str();

            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            AuthlyLogger::Log("[HASH] Calculated application hash: " + applicationHash.substr(0, 16) + "...");
        }
        catch (...) {
            applicationHash = "UNKNOWN_HASH";
            AuthlyLogger::Log("[HASH_ERROR] Failed to calculate hash");
        }
    }

    std::string GetSystemSid() {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return "UNKNOWN_SID";
        }

        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        if (dwSize == 0) {
            CloseHandle(hToken);
            return "UNKNOWN_SID";
        }

        PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
        if (!pTokenUser) {
            CloseHandle(hToken);
            return "UNKNOWN_SID";
        }

        std::string sid = "UNKNOWN_SID";
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPSTR sidStr = NULL;
            if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidStr)) {
                sid = sidStr;
                LocalFree(sidStr);
            }
        }

        free(pTokenUser);
        CloseHandle(hToken);
        return sid;
    }

    std::string GetPublicIp() {
        long long nowMs = GetTimestampMs();
        if (!cachedPublicIp.empty() && nowMs < cachedPublicIpExpiresAt) {
            return cachedPublicIp;
        }

        HINTERNET hSession = WinHttpOpen(L"AuthlyX/IPCheck", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            return "UNKNOWN_IP";
        }

        HINTERNET hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        std::string publicIp;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || !dwSize) break;

            std::vector<char> buffer(dwSize + 1);
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                publicIp.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), '\r'), publicIp.end());
        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), '\n'), publicIp.end());
        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), ' '), publicIp.end());

        if (publicIp.empty() || (publicIp.find('.') == std::string::npos && publicIp.find(':') == std::string::npos)) {
            return "UNKNOWN_IP";
        }

        cachedPublicIp = publicIp;
        cachedPublicIpExpiresAt = nowMs + 600000;
        return publicIp;
    }

    struct JsonValue {
        enum class Type { Null, Bool, Number, String, Object, Array };

        Type type = Type::Null;
        bool boolValue = false;
        std::string stringValue;
        std::map<std::string, JsonValue> objectValue;
        std::vector<JsonValue> arrayValue;
    };

    void SkipJsonWhitespace(const std::string& text, size_t& pos) {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
    }

    bool ParseJsonString(const std::string& text, size_t& pos, std::string& out) {
        if (pos >= text.size() || text[pos] != '"') return false;
        ++pos;
        std::ostringstream stream;

        while (pos < text.size()) {
            char current = text[pos++];
            if (current == '"') {
                out = stream.str();
                return true;
            }
            if (current != '\\') {
                stream << current;
                continue;
            }
            if (pos >= text.size()) return false;
            char escaped = text[pos++];
            switch (escaped) {
            case '"': stream << '"'; break;
            case '\\': stream << '\\'; break;
            case '/': stream << '/'; break;
            case 'b': stream << '\b'; break;
            case 'f': stream << '\f'; break;
            case 'n': stream << '\n'; break;
            case 'r': stream << '\r'; break;
            case 't': stream << '\t'; break;
            case 'u':
                if (pos + 4 <= text.size()) {
                    stream << '?';
                    pos += 4;
                }
                else {
                    return false;
                }
                break;
            default:
                stream << escaped;
                break;
            }
        }

        return false;
    }

    bool ParseJsonValueInternal(const std::string& text, size_t& pos, JsonValue& out) {
        SkipJsonWhitespace(text, pos);
        if (pos >= text.size()) return false;

        if (text[pos] == '"') {
            out.type = JsonValue::Type::String;
            return ParseJsonString(text, pos, out.stringValue);
        }

        if (text[pos] == '{') {
            out.type = JsonValue::Type::Object;
            ++pos;
            SkipJsonWhitespace(text, pos);
            if (pos < text.size() && text[pos] == '}') {
                ++pos;
                return true;
            }

            while (pos < text.size()) {
                std::string key;
                if (!ParseJsonString(text, pos, key)) return false;
                SkipJsonWhitespace(text, pos);
                if (pos >= text.size() || text[pos] != ':') return false;
                ++pos;

                JsonValue child;
                if (!ParseJsonValueInternal(text, pos, child)) return false;
                out.objectValue[key] = child;

                SkipJsonWhitespace(text, pos);
                if (pos < text.size() && text[pos] == '}') {
                    ++pos;
                    return true;
                }
                if (pos >= text.size() || text[pos] != ',') return false;
                ++pos;
                SkipJsonWhitespace(text, pos);
            }
            return false;
        }

        if (text[pos] == '[') {
            out.type = JsonValue::Type::Array;
            ++pos;
            SkipJsonWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ']') {
                ++pos;
                return true;
            }

            while (pos < text.size()) {
                JsonValue child;
                if (!ParseJsonValueInternal(text, pos, child)) return false;
                out.arrayValue.push_back(child);

                SkipJsonWhitespace(text, pos);
                if (pos < text.size() && text[pos] == ']') {
                    ++pos;
                    return true;
                }
                if (pos >= text.size() || text[pos] != ',') return false;
                ++pos;
                SkipJsonWhitespace(text, pos);
            }
            return false;
        }

        if (text.compare(pos, 4, "true") == 0) {
            out.type = JsonValue::Type::Bool;
            out.boolValue = true;
            pos += 4;
            return true;
        }

        if (text.compare(pos, 5, "false") == 0) {
            out.type = JsonValue::Type::Bool;
            out.boolValue = false;
            pos += 5;
            return true;
        }

        if (text.compare(pos, 4, "null") == 0) {
            out.type = JsonValue::Type::Null;
            pos += 4;
            return true;
        }

        size_t start = pos;
        while (pos < text.size() && std::string(",]} \t\r\n").find(text[pos]) == std::string::npos) {
            ++pos;
        }

        out.type = JsonValue::Type::Number;
        out.stringValue = text.substr(start, pos - start);
        return !out.stringValue.empty();
    }

    bool ParseJsonDocument(const std::string& text, JsonValue& out) {
        size_t pos = 0;
        if (!ParseJsonValueInternal(text, pos, out)) return false;
        SkipJsonWhitespace(text, pos);
        return pos == text.size();
    }

    const JsonValue* FindJsonValueRecursive(const JsonValue& node, const std::string& key) const {
        if (node.type == JsonValue::Type::Object) {
            auto it = node.objectValue.find(key);
            if (it != node.objectValue.end()) {
                return &it->second;
            }

            for (const auto& entry : node.objectValue) {
                const JsonValue* nested = FindJsonValueRecursive(entry.second, key);
                if (nested) return nested;
            }
        }

        if (node.type == JsonValue::Type::Array) {
            for (const auto& child : node.arrayValue) {
                const JsonValue* nested = FindJsonValueRecursive(child, key);
                if (nested) return nested;
            }
        }

        return nullptr;
    }

    std::string JsonValueToString(const JsonValue& value) const {
        switch (value.type) {
        case JsonValue::Type::String:
        case JsonValue::Type::Number:
            return value.stringValue;
        case JsonValue::Type::Bool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::Null:
            return "null";
        default:
            return "";
        }
    }

    std::string GetNestedJsonValue(const JsonValue& node, const std::string& key) const {
        const JsonValue* value = FindJsonValueRecursive(node, key);
        return value ? JsonValueToString(*value) : "";
    }

    std::string CanonicalizeJsonValue(const JsonValue& value) const {
        switch (value.type) {
        case JsonValue::Type::Null:
            return "null";
        case JsonValue::Type::Bool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::Number:
            return value.stringValue;
        case JsonValue::Type::String:
            return std::string("\"") + EscapeJsonString(value.stringValue) + "\"";
        case JsonValue::Type::Array: {
            std::ostringstream stream;
            stream << "[";
            for (size_t i = 0; i < value.arrayValue.size(); ++i) {
                if (i > 0) stream << ",";
                stream << CanonicalizeJsonValue(value.arrayValue[i]);
            }
            stream << "]";
            return stream.str();
        }
        case JsonValue::Type::Object: {
            std::ostringstream stream;
            stream << "{";
            bool first = true;
            for (const auto& entry : value.objectValue) {
                if (!first) stream << ",";
                first = false;
                stream << "\"" << EscapeJsonString(entry.first) << "\":" << CanonicalizeJsonValue(entry.second);
            }
            stream << "}";
            return stream.str();
        }
        }
        return "null";
    }

    std::string ExtractJsonValue(const std::string& json, const std::string& key) {
        JsonValue root;
        if (!ParseJsonDocument(json, root)) return "";

        const JsonValue* value = FindJsonValueRecursive(root, key);
        return value ? JsonValueToString(*value) : "";
    }

    void ParseResponse(const std::string& jsonResponse) {
        response.raw = jsonResponse;

        if (jsonResponse.empty()) {
            response.success = false;
            if (response.message.empty()) {
                response.message = "Empty response from server";
            }
            return;
        }

        if (jsonResponse.find("<!DOCTYPE html>") != std::string::npos ||
            jsonResponse.find("<html>") != std::string::npos) {
            response.success = false;
            response.message = "Server error - please try again later";
            return;
        }

        JsonValue root;
        if (ParseJsonDocument(jsonResponse, root)) {
            response.success = ExtractJsonValue(jsonResponse, "success") == "true";
            response.message = ExtractJsonValue(jsonResponse, "message");
            response.code = ExtractJsonValue(jsonResponse, "code");
        }

        if (response.message.empty()) {
            response.message = response.success ? "Success" : "Unknown error";
        }

        LoadUserData(jsonResponse);
        LoadVariableData(jsonResponse);
        LoadUpdateData(jsonResponse);
        LoadChatData(jsonResponse);
    }

    void LoadUserData(const std::string& jsonResponse) {
        JsonValue root;
        const bool parsed = ParseJsonDocument(jsonResponse, root);

        auto setIfPresent = [](std::string& target, const std::string& value) {
            if (!value.empty()) {
                target = value;
            }
            };

        auto getObjectValue = [&](const std::string& objectName, const std::string& key) -> std::string {
            if (!parsed || root.type != JsonValue::Type::Object) {
                return "";
            }

            auto objectIt = root.objectValue.find(objectName);
            if (objectIt == root.objectValue.end() || objectIt->second.type != JsonValue::Type::Object) {
                return "";
            }

            auto valueIt = objectIt->second.objectValue.find(key);
            if (valueIt == objectIt->second.objectValue.end()) {
                return "";
            }

            return JsonValueToString(valueIt->second);
            };

        setIfPresent(userData.username, ExtractJsonValue(jsonResponse, "username"));
        setIfPresent(userData.email, ExtractJsonValue(jsonResponse, "email"));
        setIfPresent(userData.licenseKey, ExtractJsonValue(jsonResponse, "license_key"));
        setIfPresent(userData.subscription, ExtractJsonValue(jsonResponse, "subscription"));
        setIfPresent(userData.subscriptionLevel, ExtractJsonValue(jsonResponse, "subscription_level"));
        setIfPresent(userData.lastLogin, ExtractJsonValue(jsonResponse, "last_login"));
        setIfPresent(userData.registeredAt, ExtractJsonValue(jsonResponse, "registered_at"));
        if (userData.registeredAt.empty()) {
            setIfPresent(userData.registeredAt, ExtractJsonValue(jsonResponse, "created_at"));
        }

        setIfPresent(userData.username, getObjectValue("user", "username"));
        setIfPresent(userData.email, getObjectValue("user", "email"));
        setIfPresent(userData.subscription, getObjectValue("user", "subscription"));
        setIfPresent(userData.subscriptionLevel, getObjectValue("user", "subscription_level"));
        setIfPresent(userData.licenseKey, getObjectValue("user", "linked_license_key"));
        setIfPresent(userData.lastLogin, getObjectValue("user", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("user", "registered_at"));

        setIfPresent(userData.licenseKey, getObjectValue("license", "license_key"));
        setIfPresent(userData.email, getObjectValue("license", "email"));
        setIfPresent(userData.subscription, getObjectValue("license", "subscription"));
        setIfPresent(userData.subscriptionLevel, getObjectValue("license", "subscription_level"));
        setIfPresent(userData.lastLogin, getObjectValue("license", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("license", "registered_at"));

        setIfPresent(userData.email, getObjectValue("device", "email"));
        setIfPresent(userData.subscription, getObjectValue("device", "subscription"));
        if (userData.subscription.empty()) {
            setIfPresent(userData.subscription, getObjectValue("device", "subscription_name"));
        }
        setIfPresent(userData.subscriptionLevel, getObjectValue("device", "subscription_level"));
        setIfPresent(userData.lastLogin, getObjectValue("device", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("device", "registered_at"));
        if (userData.registeredAt.empty()) {
            setIfPresent(userData.registeredAt, getObjectValue("device", "date_created"));
        }

        std::string rawDate = ExtractJsonValue(jsonResponse, "expiry_date");
        if (rawDate.empty()) {
            rawDate = getObjectValue("user", "expiry_date");
        }
        if (rawDate.empty()) {
            rawDate = getObjectValue("license", "expiry_date");
        }
        if (rawDate.empty()) {
            rawDate = getObjectValue("device", "expiry_date");
        }

        if (!rawDate.empty()) {
            std::tm tm = {};
            std::istringstream ss(rawDate.substr(0, 19));
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

            if (!ss.fail()) {
                char buffer[64];
                std::strftime(buffer, sizeof(buffer), "%d/%m/%Y", &tm);
                userData.expiryDate = std::string(buffer);
            }
            else {
                userData.expiryDate = rawDate;
            }
        }
        else {
            userData.expiryDate.clear();
        }

        userData.daysLeft = ComputeDaysLeft(rawDate);
        userData.hwid = ExtractJsonValue(jsonResponse, "sid");
        if (userData.hwid.empty()) {
            userData.hwid = ExtractJsonValue(jsonResponse, "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("user", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("user", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("license", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("license", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("device", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("device", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = GetSystemSid();
        }

        userData.ipAddress = ExtractJsonValue(jsonResponse, "ip_address");
        if (userData.ipAddress.empty()) {
            userData.ipAddress = ExtractJsonValue(jsonResponse, "ip");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("user", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("license", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("device", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = GetPublicIp();
        }

        if (userData.subscriptionLevel.empty()) {
            userData.subscriptionLevel = userData.subscription;
        }
    }

    void LoadVariableData(const std::string& jsonResponse) {
        variableData.varKey = ExtractJsonValue(jsonResponse, "var_key");
        variableData.varValue = ExtractJsonValue(jsonResponse, "var_value");
        variableData.updatedAt = ExtractJsonValue(jsonResponse, "updated_at");
    }

    void LoadUpdateData(const std::string& jsonResponse) {
        try {
            JsonValue root;
            if (!ParseJsonDocument(jsonResponse, root)) {
                updateData.available = false;
                updateData.latestVersion = "";
                updateData.downloadUrl = "";
                updateData.autoUpdateEnabled = false;
                updateData.forceUpdate = false;
                updateData.changelog = "";
                updateData.showReminder = false;
                updateData.reminderMessage = "";
                updateData.allowedUntil = "";
                return;
            }

            const JsonValue* updateNode = FindJsonValueRecursive(root, "update");
            if (!updateNode || updateNode->type != JsonValue::Type::Object) {
                updateData.latestVersion = GetNestedJsonValue(root, "server_version");
                if (updateData.latestVersion.empty()) {
                    updateData.latestVersion = GetNestedJsonValue(root, "version");
                }
                updateData.available = GetNestedJsonValue(root, "auto_update_enabled") == "true" ||
                    !GetNestedJsonValue(root, "auto_update_download_url").empty() ||
                    !updateData.latestVersion.empty();
                updateData.downloadUrl = GetNestedJsonValue(root, "auto_update_download_url");
                updateData.autoUpdateEnabled = GetNestedJsonValue(root, "auto_update_enabled") == "true";
                updateData.forceUpdate = GetNestedJsonValue(root, "force_update") == "true";
                updateData.changelog.clear();
                updateData.showReminder = false;
                updateData.reminderMessage.clear();
                updateData.allowedUntil.clear();
                return;
            }

            updateData.available = GetNestedJsonValue(*updateNode, "available") == "true";
            updateData.latestVersion = GetNestedJsonValue(*updateNode, "latest_version");
            updateData.downloadUrl = GetNestedJsonValue(*updateNode, "download_url");
            updateData.autoUpdateEnabled = GetNestedJsonValue(*updateNode, "auto_update_enabled") == "true";
            updateData.forceUpdate = GetNestedJsonValue(*updateNode, "force_update") == "true";
            updateData.changelog = GetNestedJsonValue(*updateNode, "changelog");
            updateData.showReminder = GetNestedJsonValue(*updateNode, "show_reminder") == "true";
            updateData.reminderMessage = GetNestedJsonValue(*updateNode, "reminder_message");
            updateData.allowedUntil = NormalizeOptionalText(GetNestedJsonValue(*updateNode, "allowed_until"));

            if (updateData.available) {
                AuthlyLogger::Log("[UPDATE] Update available: " + updateData.latestVersion + ", Force: " + (updateData.forceUpdate ? "true" : "false"));
            }
        }
        catch (...) {
            AuthlyLogger::Log("[UPDATE_ERROR] Failed to load update data");
        }
    }

    void LoadChatData(const std::string& jsonResponse) {
        try {
            JsonValue root;
            if (!ParseJsonDocument(jsonResponse, root)) {
                chatMessages.channelName = "";
                chatMessages.messages.clear();
                chatMessages.count = 0;
                chatMessages.nextCursor.clear();
                chatMessages.hasMore = false;
                return;
            }

            const JsonValue* dataNode = FindJsonValueRecursive(root, "data");
            if (!dataNode || dataNode->type != JsonValue::Type::Object) {
                chatMessages.messages.clear();
                chatMessages.count = 0;
                chatMessages.nextCursor.clear();
                chatMessages.hasMore = false;
                return;
            }

            chatMessages.channelName = GetNestedJsonValue(*dataNode, "channel_name");
            chatMessages.nextCursor = GetNestedJsonValue(*dataNode, "next_cursor");
            chatMessages.hasMore = GetNestedJsonValue(*dataNode, "has_more") == "true";
            chatMessages.messages.clear();
            const JsonValue* messagesNode = FindJsonValueRecursive(*dataNode, "messages");
            if (messagesNode && messagesNode->type == JsonValue::Type::Array) {
                for (const auto& item : messagesNode->arrayValue) {
                    if (item.type != JsonValue::Type::Object) continue;
                    ChatMessage msg;
                    std::string id = GetNestedJsonValue(item, "id");
                    msg.id = id.empty() ? 0 : std::atoi(id.c_str());
                    msg.username = GetNestedJsonValue(item, "username");
                    msg.message = GetNestedJsonValue(item, "message");
                    msg.createdAt = GetNestedJsonValue(item, "created_at");
                    chatMessages.messages.push_back(msg);
                }
            }

            chatMessages.count = static_cast<int>(chatMessages.messages.size());
        }
        catch (...) {
            AuthlyLogger::Log("[CHAT_DATA_ERROR] Failed to load chat data");
            chatMessages.messages.clear();
            chatMessages.count = 0;
        }
    }

    static std::vector<int> ParseSemverParts(const std::string& versionString) {
        std::vector<int> parts;
        std::string token;
        token.reserve(16);

        auto flush = [&]() {
            if (token.empty()) return;
            try {
                parts.push_back(std::stoi(token));
            }
            catch (...) {
                parts.push_back(0);
            }
            token.clear();
            };

        for (char c : versionString) {
            if (c >= '0' && c <= '9') {
                token.push_back(c);
                continue;
            }
            if (c == '.') {
                flush();
                continue;
            }
            break;
        }
        flush();

        while (parts.size() < 3) parts.push_back(0);
        return parts;
    }

    static int CompareSemver(const std::string& a, const std::string& b) {
        const std::vector<int> ap = ParseSemverParts(a);
        const std::vector<int> bp = ParseSemverParts(b);
        const size_t n = std::max(ap.size(), bp.size());
        for (size_t i = 0; i < n; i++) {
            const int av = i < ap.size() ? ap[i] : 0;
            const int bv = i < bp.size() ? bp[i] : 0;
            if (av < bv) return -1;
            if (av > bv) return 1;
        }
        return 0;
    }

    bool HasWhitelistedUpdateMessage() const {
        return updateData.showReminder || !updateData.allowedUntil.empty();
    }

    static std::string NormalizeOptionalText(const std::string& value) {
        std::string trimmed = value;
        trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](unsigned char ch) {
            return !std::isspace(ch);
            }));
        trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
            }).base(), trimmed.end());

        std::string lower = trimmed;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
            });

        return lower == "null" ? "" : value;
    }

    bool IsAutoUpdateEnabled() const {
        return updateData.autoUpdateEnabled;
    }

    static std::string FormatDisplayDate(const std::string& rawDate) {
        if (rawDate.empty()) return rawDate;
        std::string ts = rawDate;
        if (!ts.empty() && ts.back() == 'Z') {
            ts.pop_back();
        }
        if (ts.size() >= 19) {
            ts = ts.substr(0, 19);
        }

        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) return rawDate;

        char buffer[64];
        if (std::strftime(buffer, sizeof(buffer), "%B %d, %Y", &tm) == 0) {
            return rawDate;
        }

        std::string formatted = buffer;
        size_t zeroPos = formatted.find(" 0");
        if (zeroPos != std::string::npos) {
            formatted.erase(zeroPos + 1, 1);
        }
        return formatted;
    }

    std::string BuildWhitelistedUpdateMessage() const {
        const std::string currentVersion = version.empty() ? "Not provided" : version;
        const std::string latestVersion = updateData.latestVersion.empty() ? "Not provided" : updateData.latestVersion;
        std::string base;
        if (!updateData.allowedUntil.empty()) {
            base = "A new update is available, and this build will keep working until " + FormatDisplayDate(updateData.allowedUntil) + ".";
        }
        else {
            base = "A new update is available, and this build still has access.";
        }

        base += "\n\nCurrent Version: " + currentVersion + "\nLatest Version: " + latestVersion;

        if (!IsAutoUpdateEnabled()) {
            return base;
        }

        return base + "\n\nWould you like to download the latest version now?";
    }

    static void EnsureConsole() {
        if (GetConsoleWindow() == NULL) {
            AllocConsole();
        }

        FILE* outputFile = nullptr;
        FILE* inputFile = nullptr;
        freopen_s(&outputFile, "CONOUT$", "w", stdout);
        freopen_s(&inputFile, "CONIN$", "r", stdin);
    }

    static void OpenUrl(const std::string& url) {
        if (url.empty()) return;
        std::wstring wideUrl(url.begin(), url.end());
        ShellExecuteW(NULL, L"open", wideUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }

    void OpenDownloadUrl() {
        if (!updateData.downloadUrl.empty()) {
            OpenUrl(updateData.downloadUrl);
        }
    }

    void ShowRequiredUpdateConsole(const std::string& message) {
        EnsureConsole();
        std::cout << message << std::endl;
        std::cout << "Current Version: " << version << std::endl;
        if (!updateData.latestVersion.empty()) {
            std::cout << "Latest version: " << updateData.latestVersion << std::endl;
        }

        if (!IsAutoUpdateEnabled() || updateData.downloadUrl.empty()) {
            return;
        }

        std::cout << "1. Download Latest" << std::endl;
        std::cout << "2. Exit" << std::endl;
        std::cout << "Select an option (1 or 2): ";

        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "1") {
            OpenDownloadUrl();
        }
    }

    void ShowVersionMismatchConsole(const std::string& message) {
        EnsureConsole();
        std::cout << message << std::endl;
        std::cout << "Current Version: " << version << std::endl;
        if (!updateData.latestVersion.empty()) {
            std::cout << "Server Version: " << updateData.latestVersion << std::endl;
        }
    }

    void ShowWhitelistedUpdatePrompt() {
        const std::string msg = BuildWhitelistedUpdateMessage();

        if (IsAutoUpdateEnabled() && !updateData.downloadUrl.empty()) {
            int r = MessageBoxA(NULL, msg.c_str(), "AuthlyX Update", MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);
            if (r == IDYES) {
                OpenDownloadUrl();
            }
            return;
        }

        MessageBoxA(NULL, msg.c_str(), "AuthlyX Update", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    }

    void Error(const std::string& message) {
        AuthlyLogger::Log("[ERROR] " + message);

        std::string cmd = "cmd.exe /c start cmd /C \"color 4 && title AuthlyX Error && echo " +
            message + " && timeout /t 5\"";

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (pi.hProcess) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    int ComputeDaysLeft(const std::string& expiryDate) {
        if (expiryDate.empty()) return 0;
        std::string ts = expiryDate;
        if (ts.size() >= 19) {
            ts = ts.substr(0, 19);
        }
        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) return 0;
        time_t expiry = _mkgmtime(&tm);
        if (expiry <= 0) return 0;
        time_t now = time(nullptr);
        double diff = difftime(expiry, now);
        int days = static_cast<int>(std::ceil(diff / 86400.0));
        return days < 0 ? 0 : days;
    }

    std::string GetSessionId() const { return sessionId; }
    std::string GetCurrentApplicationHash() const { return applicationHash; }
    bool IsInitialized() const { return initialized; }
    std::string GetAppName() const { return appName; }

    bool IsUpdateAvailable() const { return updateData.available; }
    UpdateData GetUpdateInfo() const { return updateData; }

    std::string GetChats(const std::string& channelName) {
        return GetChats(channelName, 100, "");
    }

    std::string GetChats(const std::string& channelName, int limit, const std::string& cursor) {
        CheckInit();
        if (!initialized) return "";
        if (channelName.empty()) return "Channel cannot be empty";

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"channel_name", channelName},
            {"limit", std::to_string(limit > 0 ? limit : 100)}
        };

        if (!cursor.empty()) {
            payload["cursor"] = cursor;
        }

        std::string responseStr = PostJson("chats/get", BuildJson(payload));
        ParseResponse(responseStr);
        return responseStr;
    }

    void SendChat(const std::string& message) {
        SendChat(message, "global");
    }

    void SendChat(const std::string& message, const std::string& channelName) {
        if (message.empty() || channelName.empty()) return;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"channel_name", channelName},
            {"message", message}
        };
        std::string responseStr = PostJson("chats/send", BuildJson(payload));
        ParseResponse(responseStr);
    }

private:
    std::string BuildJson(const std::map<std::string, std::string>& data) const {
        std::string json = "{";
        for (auto it = data.begin(); it != data.end(); ++it) {
            if (it != data.begin()) json += ",";
            json += "\"" + it->first + "\":\"" + EscapeJsonString(it->second) + "\"";
        }
        json += "}";
        return json;
    }

    std::string EscapeJsonString(const std::string& input) const {
        std::string output;
        for (char c : input) {
            switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
            }
        }
        return output;
    }

    bool loggingEnabled = false;
};

#endif // __cplusplus

#ifndef AUTHLYX_C_API_DECL
#define AUTHLYX_C_API_DECL

#ifdef __cplusplus
#define AUTHLYX_EXTERN_C extern "C"
#else
#define AUTHLYX_EXTERN_C
#endif

#if defined(_WIN32) && defined(AUTHLYX_BUILD_DLL)
#define AUTHLYX_C_API __declspec(dllexport)
#elif defined(_WIN32) && defined(AUTHLYX_USE_DLL)
#define AUTHLYX_C_API __declspec(dllimport)
#else
#define AUTHLYX_C_API
#endif

#if defined(__cplusplus) && !defined(AUTHLYX_SOURCE_BUILD) && !defined(AUTHLYX_USE_DLL)
static inline void* AuthlyX_Create(const char* ownerId, const char* appName, const char* version, const char* secret) {
    return new AuthlyX(
        ownerId ? ownerId : "",
        appName ? appName : "",
        version ? version : "",
        secret ? secret : "");
}

static inline int AuthlyX_Init(void* instance) {
    return instance ? (reinterpret_cast<AuthlyX*>(instance)->Init() ? 1 : 0) : 0;
}

static inline int AuthlyX_Login(void* instance, const char* identifier, const char* password) {
    if (!instance || !identifier || !password) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Login(identifier, password) ? 1 : 0;
}

static inline int AuthlyX_LicenseLogin(void* instance, const char* licenseKey) {
    if (!instance || !licenseKey) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->LicenseLogin(licenseKey) ? 1 : 0;
}

static inline int AuthlyX_DeviceLogin(void* instance, const char* deviceType, const char* deviceId) {
    if (!instance || !deviceType || !deviceId) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->DeviceLogin(deviceType, deviceId) ? 1 : 0;
}

static inline int AuthlyX_Authenticate(void* instance, const char* identifier, const char* password, const char* deviceType) {
    if (!instance || !identifier) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Authenticate(
        identifier,
        password ? password : "",
        deviceType ? deviceType : "") ? 1 : 0;
}

static inline int AuthlyX_ChangePassword(void* instance, const char* oldPassword, const char* newPassword) {
    if (!instance || !oldPassword || !newPassword) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->ChangePassword(oldPassword, newPassword) ? 1 : 0;
}

static inline const char* AuthlyX_GetMessage(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->response.message.c_str() : "";
}

static inline const char* AuthlyX_GetUsername(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.username.c_str() : "";
}

static inline const char* AuthlyX_GetLicenseKey(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.licenseKey.c_str() : "";
}

static inline void AuthlyX_Destroy(void* instance) {
    delete reinterpret_cast<AuthlyX*>(instance);
}
#else
typedef void* AuthlyXHandle;

AUTHLYX_EXTERN_C AUTHLYX_C_API void* AuthlyX_Create(const char* ownerId, const char* appName, const char* version, const char* secret);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Init(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Login(void* instance, const char* identifier, const char* password);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_LicenseLogin(void* instance, const char* licenseKey);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_DeviceLogin(void* instance, const char* deviceType, const char* deviceId);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Authenticate(void* instance, const char* identifier, const char* password, const char* deviceType);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_ChangePassword(void* instance, const char* oldPassword, const char* newPassword);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetMessage(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetUsername(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetLicenseKey(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API void AuthlyX_Destroy(void* instance);
#endif

#endif
