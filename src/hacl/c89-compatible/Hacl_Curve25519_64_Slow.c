/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "Hacl_Curve25519_64_Slow.h"

typedef struct K___uint64_t_uint64_t_uint64_t_uint64_t_s
{
  uint64_t fst;
  uint64_t snd;
  uint64_t thd;
  uint64_t f3;
}
K___uint64_t_uint64_t_uint64_t_uint64_t;

typedef struct K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_s
{
  uint64_t fst;
  uint64_t snd;
  uint64_t thd;
  uint64_t f3;
  uint64_t f4;
  uint64_t f5;
  uint64_t f6;
  uint64_t f7;
}
K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t;

typedef struct K___uint64_t_uint64_t_s
{
  uint64_t fst;
  uint64_t snd;
}
K___uint64_t_uint64_t;

inline static K___uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_addcarry(uint64_t x, uint64_t y, uint64_t cin)
{
  uint64_t res1 = x + cin;
  uint64_t c;
  if (res1 < cin)
  {
    c = (uint64_t)1U;
  }
  else
  {
    c = (uint64_t)0U;
  }
  {
    uint64_t res = res1 + y;
    uint64_t c1;
    if (res < res1)
    {
      c1 = c + (uint64_t)1U;
    }
    else
    {
      c1 = c;
    }
    {
      K___uint64_t_uint64_t lit;
      lit.fst = res;
      lit.snd = c1;
      return lit;
    }
  }
}

inline static K___uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_subborrow(uint64_t x, uint64_t y, uint64_t cin)
{
  uint64_t res = x - y - cin;
  uint64_t c;
  if (cin == (uint64_t)1U)
  {
    if (x <= y)
    {
      c = (uint64_t)1U;
    }
    else
    {
      c = (uint64_t)0U;
    }
  }
  else if (x < y)
  {
    c = (uint64_t)1U;
  }
  else
  {
    c = (uint64_t)0U;
  }
  {
    K___uint64_t_uint64_t lit;
    lit.fst = res;
    lit.snd = c;
    return lit;
  }
}

inline static K___uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_mul64(uint64_t x, uint64_t y)
{
  FStar_UInt128_uint128 res = FStar_UInt128_mul_wide(x, y);
  K___uint64_t_uint64_t lit;
  lit.fst = FStar_UInt128_uint128_to_uint64(res);
  lit.snd = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res, (uint32_t)64U));
  return lit;
}

inline static K___uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_add0carry(uint64_t x, uint64_t y)
{
  uint64_t res = x + y;
  uint64_t c;
  if (res < x)
  {
    c = (uint64_t)1U;
  }
  else
  {
    c = (uint64_t)0U;
  }
  {
    K___uint64_t_uint64_t lit;
    lit.fst = res;
    lit.snd = c;
    return lit;
  }
}

typedef struct K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t_s
{
  uint64_t fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t snd;
}
K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t;

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_add1(K___uint64_t_uint64_t_uint64_t_uint64_t f, uint64_t cin)
{
  uint64_t f0 = f.fst;
  uint64_t f1 = f.snd;
  uint64_t f2 = f.thd;
  uint64_t f3 = f.f3;
  K___uint64_t_uint64_t scrut = Hacl_Spec_Curve25519_Field64_Core_add0carry(f0, cin);
  uint64_t o0 = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t scrut0 = Hacl_Spec_Curve25519_Field64_Core_add0carry(f1, c0);
  uint64_t o1 = scrut0.fst;
  uint64_t c1 = scrut0.snd;
  K___uint64_t_uint64_t scrut1 = Hacl_Spec_Curve25519_Field64_Core_add0carry(f2, c1);
  uint64_t o2 = scrut1.fst;
  uint64_t c2 = scrut1.snd;
  K___uint64_t_uint64_t scrut2 = Hacl_Spec_Curve25519_Field64_Core_add0carry(f3, c2);
  uint64_t o3 = scrut2.fst;
  uint64_t c3 = scrut2.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  out.fst = o0;
  out.snd = o1;
  out.thd = o2;
  out.f3 = o3;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c3;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_sub1(K___uint64_t_uint64_t_uint64_t_uint64_t f, uint64_t cin)
{
  uint64_t f0 = f.fst;
  uint64_t f1 = f.snd;
  uint64_t f2 = f.thd;
  uint64_t f3 = f.f3;
  K___uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_subborrow(f0, cin, (uint64_t)0U);
  uint64_t o0 = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t
  scrut0 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f1, (uint64_t)0U, c0);
  uint64_t o1 = scrut0.fst;
  uint64_t c1 = scrut0.snd;
  K___uint64_t_uint64_t
  scrut1 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f2, (uint64_t)0U, c1);
  uint64_t o2 = scrut1.fst;
  uint64_t c2 = scrut1.snd;
  K___uint64_t_uint64_t
  scrut2 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f3, (uint64_t)0U, c2);
  uint64_t o3 = scrut2.fst;
  uint64_t c3 = scrut2.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  out.fst = o0;
  out.snd = o1;
  out.thd = o2;
  out.f3 = o3;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c3;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_mul1(K___uint64_t_uint64_t_uint64_t_uint64_t f, uint64_t u)
{
  uint64_t f0 = f.fst;
  uint64_t f1 = f.snd;
  uint64_t f2 = f.thd;
  uint64_t f3 = f.f3;
  K___uint64_t_uint64_t scrut0 = Hacl_Spec_Curve25519_Field64_Core_mul64(f0, u);
  uint64_t l0 = scrut0.fst;
  uint64_t h0 = scrut0.snd;
  K___uint64_t_uint64_t scrut1 = Hacl_Spec_Curve25519_Field64_Core_mul64(f1, u);
  uint64_t l1 = scrut1.fst;
  uint64_t h1 = scrut1.snd;
  K___uint64_t_uint64_t scrut2 = Hacl_Spec_Curve25519_Field64_Core_mul64(f2, u);
  uint64_t l2 = scrut2.fst;
  uint64_t h2 = scrut2.snd;
  K___uint64_t_uint64_t scrut3 = Hacl_Spec_Curve25519_Field64_Core_mul64(f3, u);
  uint64_t l3 = scrut3.fst;
  uint64_t h3 = scrut3.snd;
  uint64_t o0 = l0;
  K___uint64_t_uint64_t scrut = Hacl_Spec_Curve25519_Field64_Core_addcarry(l1, h0, (uint64_t)0U);
  uint64_t o1 = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t scrut4 = Hacl_Spec_Curve25519_Field64_Core_addcarry(l2, h1, c0);
  uint64_t o2 = scrut4.fst;
  uint64_t c1 = scrut4.snd;
  K___uint64_t_uint64_t scrut5 = Hacl_Spec_Curve25519_Field64_Core_addcarry(l3, h2, c1);
  uint64_t o3 = scrut5.fst;
  uint64_t c2 = scrut5.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  uint64_t c3;
  out.fst = o0;
  out.snd = o1;
  out.thd = o2;
  out.f3 = o3;
  c3 = h3 + c2;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c3;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_mul1_add(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  uint64_t u2,
  K___uint64_t_uint64_t_uint64_t_uint64_t f3
)
{
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut0 = Hacl_Spec_Curve25519_Field64_Core_mul1(f1, u2);
  uint64_t c = scrut0.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut0.snd;
  uint64_t o0 = out0.fst;
  uint64_t o1 = out0.snd;
  uint64_t o2 = out0.thd;
  uint64_t o3 = out0.f3;
  uint64_t f30 = f3.fst;
  uint64_t f31 = f3.snd;
  uint64_t f32 = f3.thd;
  uint64_t f33 = f3.f3;
  K___uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_addcarry(f30, o0, (uint64_t)0U);
  uint64_t o0_ = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t scrut1 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f31, o1, c0);
  uint64_t o1_ = scrut1.fst;
  uint64_t c1 = scrut1.snd;
  K___uint64_t_uint64_t scrut2 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f32, o2, c1);
  uint64_t o2_ = scrut2.fst;
  uint64_t c2 = scrut2.snd;
  K___uint64_t_uint64_t scrut3 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f33, o3, c2);
  uint64_t o3_ = scrut3.fst;
  uint64_t c3 = scrut3.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  uint64_t c4;
  out.fst = o0_;
  out.snd = o1_;
  out.thd = o2_;
  out.f3 = o3_;
  c4 = c + c3;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c4;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_carry_pass(
  K___uint64_t_uint64_t_uint64_t_uint64_t f,
  uint64_t cin
)
{
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_add1(f, cin * (uint64_t)38U);
  uint64_t carry = scrut.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut.snd;
  uint64_t o0 = out0.fst;
  uint64_t o1 = out0.snd;
  uint64_t o2 = out0.thd;
  uint64_t o3 = out0.f3;
  uint64_t o0_ = o0 + carry * (uint64_t)38U;
  K___uint64_t_uint64_t_uint64_t_uint64_t lit;
  lit.fst = o0_;
  lit.snd = o1;
  lit.thd = o2;
  lit.f3 = o3;
  return lit;
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_carry_wide(
  K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t f
)
{
  uint64_t f0 = f.fst;
  uint64_t f1 = f.snd;
  uint64_t f2 = f.thd;
  uint64_t f3 = f.f3;
  uint64_t f4 = f.f4;
  uint64_t f5 = f.f5;
  uint64_t f6 = f.f6;
  uint64_t f7 = f.f7;
  K___uint64_t_uint64_t_uint64_t_uint64_t lit0;
  lit0.fst = f4;
  lit0.snd = f5;
  lit0.thd = f6;
  lit0.f3 = f7;
  {
    K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
    uint64_t c0;
    K___uint64_t_uint64_t_uint64_t_uint64_t out0;
    K___uint64_t_uint64_t_uint64_t_uint64_t out1;
    lit.fst = f0;
    lit.snd = f1;
    lit.thd = f2;
    lit.f3 = f3;
    scrut = Hacl_Spec_Curve25519_Field64_Core_mul1_add(lit0, (uint64_t)38U, lit);
    c0 = scrut.fst;
    out0 = scrut.snd;
    out1 = Hacl_Spec_Curve25519_Field64_Core_carry_pass(out0, c0);
    return out1;
  }
}

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_add4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  K___uint64_t_uint64_t_uint64_t_uint64_t f2
)
{
  uint64_t f10 = f1.fst;
  uint64_t f11 = f1.snd;
  uint64_t f12 = f1.thd;
  uint64_t f13 = f1.f3;
  uint64_t f20 = f2.fst;
  uint64_t f21 = f2.snd;
  uint64_t f22 = f2.thd;
  uint64_t f23 = f2.f3;
  K___uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_addcarry(f10, f20, (uint64_t)0U);
  uint64_t o0 = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t scrut0 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f11, f21, c0);
  uint64_t o1 = scrut0.fst;
  uint64_t c1 = scrut0.snd;
  K___uint64_t_uint64_t scrut1 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f12, f22, c1);
  uint64_t o2 = scrut1.fst;
  uint64_t c2 = scrut1.snd;
  K___uint64_t_uint64_t scrut2 = Hacl_Spec_Curve25519_Field64_Core_addcarry(f13, f23, c2);
  uint64_t o3 = scrut2.fst;
  uint64_t c3 = scrut2.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  out.fst = o0;
  out.snd = o1;
  out.thd = o2;
  out.f3 = o3;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c3;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_fadd4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  K___uint64_t_uint64_t_uint64_t_uint64_t f2
)
{
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_add4(f1, f2);
  uint64_t c0 = scrut.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t
  out = Hacl_Spec_Curve25519_Field64_Core_carry_pass(out0, c0);
  return out;
}

static K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_sub4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  K___uint64_t_uint64_t_uint64_t_uint64_t f2
)
{
  uint64_t f10 = f1.fst;
  uint64_t f11 = f1.snd;
  uint64_t f12 = f1.thd;
  uint64_t f13 = f1.f3;
  uint64_t f20 = f2.fst;
  uint64_t f21 = f2.snd;
  uint64_t f22 = f2.thd;
  uint64_t f23 = f2.f3;
  K___uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_subborrow(f10, f20, (uint64_t)0U);
  uint64_t o0 = scrut.fst;
  uint64_t c0 = scrut.snd;
  K___uint64_t_uint64_t scrut0 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f11, f21, c0);
  uint64_t o1 = scrut0.fst;
  uint64_t c1 = scrut0.snd;
  K___uint64_t_uint64_t scrut1 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f12, f22, c1);
  uint64_t o2 = scrut1.fst;
  uint64_t c2 = scrut1.snd;
  K___uint64_t_uint64_t scrut2 = Hacl_Spec_Curve25519_Field64_Core_subborrow(f13, f23, c2);
  uint64_t o3 = scrut2.fst;
  uint64_t c3 = scrut2.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t out;
  out.fst = o0;
  out.snd = o1;
  out.thd = o2;
  out.f3 = o3;
  {
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    lit.fst = c3;
    lit.snd = out;
    return lit;
  }
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_fsub4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  K___uint64_t_uint64_t_uint64_t_uint64_t f2
)
{
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_sub4(f1, f2);
  uint64_t c0 = scrut.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut.snd;
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut0 = Hacl_Spec_Curve25519_Field64_Core_sub1(out0, c0 * (uint64_t)38U);
  uint64_t c1 = scrut0.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out1 = scrut0.snd;
  uint64_t o0 = out1.fst;
  uint64_t o1 = out1.snd;
  uint64_t o2 = out1.thd;
  uint64_t o3 = out1.f3;
  uint64_t o0_ = o0 - c1 * (uint64_t)38U;
  K___uint64_t_uint64_t_uint64_t_uint64_t lit;
  lit.fst = o0_;
  lit.snd = o1;
  lit.thd = o2;
  lit.f3 = o3;
  return lit;
}

static K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_mul4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f,
  K___uint64_t_uint64_t_uint64_t_uint64_t r
)
{
  uint64_t f0 = f.fst;
  uint64_t f1 = f.snd;
  uint64_t f2 = f.thd;
  uint64_t f3 = f.f3;
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut0 = Hacl_Spec_Curve25519_Field64_Core_mul1(r, f0);
  uint64_t c0 = scrut0.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut0.snd;
  uint64_t o00 = out0.fst;
  uint64_t o01 = out0.snd;
  uint64_t o02 = out0.thd;
  uint64_t o03 = out0.f3;
  K___uint64_t_uint64_t_uint64_t_uint64_t lit0;
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t scrut1;
  uint64_t c1;
  K___uint64_t_uint64_t_uint64_t_uint64_t out1;
  uint64_t o11;
  uint64_t o12;
  uint64_t o13;
  uint64_t o14;
  lit0.fst = o01;
  lit0.snd = o02;
  lit0.thd = o03;
  lit0.f3 = c0;
  scrut1 = Hacl_Spec_Curve25519_Field64_Core_mul1_add(r, f1, lit0);
  c1 = scrut1.fst;
  out1 = scrut1.snd;
  o11 = out1.fst;
  o12 = out1.snd;
  o13 = out1.thd;
  o14 = out1.f3;
  {
    K___uint64_t_uint64_t_uint64_t_uint64_t lit1;
    K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t scrut2;
    uint64_t c2;
    K___uint64_t_uint64_t_uint64_t_uint64_t out2;
    uint64_t o22;
    uint64_t o23;
    uint64_t o24;
    uint64_t o25;
    lit1.fst = o12;
    lit1.snd = o13;
    lit1.thd = o14;
    lit1.f3 = c1;
    scrut2 = Hacl_Spec_Curve25519_Field64_Core_mul1_add(r, f2, lit1);
    c2 = scrut2.fst;
    out2 = scrut2.snd;
    o22 = out2.fst;
    o23 = out2.snd;
    o24 = out2.thd;
    o25 = out2.f3;
    {
      K___uint64_t_uint64_t_uint64_t_uint64_t lit2;
      K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
      uint64_t c3;
      K___uint64_t_uint64_t_uint64_t_uint64_t out3;
      uint64_t o33;
      uint64_t o34;
      uint64_t o35;
      uint64_t o36;
      uint64_t o37;
      lit2.fst = o23;
      lit2.snd = o24;
      lit2.thd = o25;
      lit2.f3 = c2;
      scrut = Hacl_Spec_Curve25519_Field64_Core_mul1_add(r, f3, lit2);
      c3 = scrut.fst;
      out3 = scrut.snd;
      o33 = out3.fst;
      o34 = out3.snd;
      o35 = out3.thd;
      o36 = out3.f3;
      o37 = c3;
      {
        K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t lit;
        lit.fst = o00;
        lit.snd = o11;
        lit.thd = o22;
        lit.f3 = o33;
        lit.f4 = o34;
        lit.f5 = o35;
        lit.f6 = o36;
        lit.f7 = o37;
        return lit;
      }
    }
  }
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_fmul4(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  K___uint64_t_uint64_t_uint64_t_uint64_t r
)
{
  K___uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t_uint64_t
  tmp = Hacl_Spec_Curve25519_Field64_Core_mul4(f1, r);
  K___uint64_t_uint64_t_uint64_t_uint64_t
  out = Hacl_Spec_Curve25519_Field64_Core_carry_wide(tmp);
  return out;
}

static K___uint64_t_uint64_t_uint64_t_uint64_t
Hacl_Spec_Curve25519_Field64_Core_fmul14(
  K___uint64_t_uint64_t_uint64_t_uint64_t f1,
  uint64_t f2
)
{
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t
  scrut = Hacl_Spec_Curve25519_Field64_Core_mul1(f1, f2);
  uint64_t c0 = scrut.fst;
  K___uint64_t_uint64_t_uint64_t_uint64_t out0 = scrut.snd;
  K___uint64_t_uint64_t_uint64_t_uint64_t
  out1 = Hacl_Spec_Curve25519_Field64_Core_carry_pass(out0, c0);
  return out1;
}

inline static uint64_t
Hacl_Impl_Curve25519_Field64_Hacl_add1(uint64_t *out, uint64_t *f1, uint64_t f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  K___uint64_t_uint64_t_uint64_t_uint64_t lit;
  K___uint64_t_K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
  uint64_t o3;
  uint64_t o2;
  uint64_t o1;
  uint64_t o0;
  uint64_t carry;
  lit.fst = f10;
  lit.snd = f11;
  lit.thd = f12;
  lit.f3 = f13;
  scrut = Hacl_Spec_Curve25519_Field64_Core_add1(lit, f2);
  o3 = scrut.snd.f3;
  o2 = scrut.snd.thd;
  o1 = scrut.snd.snd;
  o0 = scrut.snd.fst;
  carry = scrut.fst;
  out[0U] = o0;
  out[1U] = o1;
  out[2U] = o2;
  out[3U] = o3;
  return carry;
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fadd(uint64_t *out, uint64_t *f1, uint64_t *f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  uint64_t f23 = f2[3U];
  K___uint64_t_uint64_t_uint64_t_uint64_t lit0;
  lit0.fst = f10;
  lit0.snd = f11;
  lit0.thd = f12;
  lit0.f3 = f13;
  {
    K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
    uint64_t o0;
    uint64_t o1;
    uint64_t o2;
    uint64_t o3;
    lit.fst = f20;
    lit.snd = f21;
    lit.thd = f22;
    lit.f3 = f23;
    scrut = Hacl_Spec_Curve25519_Field64_Core_fadd4(lit0, lit);
    o0 = scrut.fst;
    o1 = scrut.snd;
    o2 = scrut.thd;
    o3 = scrut.f3;
    out[0U] = o0;
    out[1U] = o1;
    out[2U] = o2;
    out[3U] = o3;
  }
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fsub(uint64_t *out, uint64_t *f1, uint64_t *f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  uint64_t f23 = f2[3U];
  K___uint64_t_uint64_t_uint64_t_uint64_t lit0;
  lit0.fst = f10;
  lit0.snd = f11;
  lit0.thd = f12;
  lit0.f3 = f13;
  {
    K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
    uint64_t o0;
    uint64_t o1;
    uint64_t o2;
    uint64_t o3;
    lit.fst = f20;
    lit.snd = f21;
    lit.thd = f22;
    lit.f3 = f23;
    scrut = Hacl_Spec_Curve25519_Field64_Core_fsub4(lit0, lit);
    o0 = scrut.fst;
    o1 = scrut.snd;
    o2 = scrut.thd;
    o3 = scrut.f3;
    out[0U] = o0;
    out[1U] = o1;
    out[2U] = o2;
    out[3U] = o3;
  }
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fmul(
  uint64_t *out,
  uint64_t *f1,
  uint64_t *f2,
  uint64_t *tmp
)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  uint64_t f23 = f2[3U];
  K___uint64_t_uint64_t_uint64_t_uint64_t lit0;
  lit0.fst = f10;
  lit0.snd = f11;
  lit0.thd = f12;
  lit0.f3 = f13;
  {
    K___uint64_t_uint64_t_uint64_t_uint64_t lit;
    K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
    uint64_t o0;
    uint64_t o1;
    uint64_t o2;
    uint64_t o3;
    lit.fst = f20;
    lit.snd = f21;
    lit.thd = f22;
    lit.f3 = f23;
    scrut = Hacl_Spec_Curve25519_Field64_Core_fmul4(lit0, lit);
    o0 = scrut.fst;
    o1 = scrut.snd;
    o2 = scrut.thd;
    o3 = scrut.f3;
    out[0U] = o0;
    out[1U] = o1;
    out[2U] = o2;
    out[3U] = o3;
  }
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fmul2(
  uint64_t *out,
  uint64_t *f1,
  uint64_t *f2,
  uint64_t *tmp
)
{
  uint64_t *out1 = out;
  uint64_t *out2 = out + (uint32_t)4U;
  uint64_t *f11 = f1;
  uint64_t *f12 = f1 + (uint32_t)4U;
  uint64_t *f21 = f2;
  uint64_t *f22 = f2 + (uint32_t)4U;
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(out1, f11, f21, tmp);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(out2, f12, f22, tmp);
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fmul1(uint64_t *out, uint64_t *f1, uint64_t f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  K___uint64_t_uint64_t_uint64_t_uint64_t lit;
  K___uint64_t_uint64_t_uint64_t_uint64_t scrut;
  uint64_t o0;
  uint64_t o1;
  uint64_t o2;
  uint64_t o3;
  lit.fst = f10;
  lit.snd = f11;
  lit.thd = f12;
  lit.f3 = f13;
  scrut = Hacl_Spec_Curve25519_Field64_Core_fmul14(lit, f2);
  o0 = scrut.fst;
  o1 = scrut.snd;
  o2 = scrut.thd;
  o3 = scrut.f3;
  out[0U] = o0;
  out[1U] = o1;
  out[2U] = o2;
  out[3U] = o3;
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fsqr(uint64_t *out, uint64_t *f1, uint64_t *tmp)
{
  uint64_t tmp1[16U] = { 0U };
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(out, f1, f1, tmp1);
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_fsqr2(uint64_t *out, uint64_t *f, uint64_t *tmp)
{
  Hacl_Impl_Curve25519_Field64_Hacl_fmul2(out, f, f, tmp);
}

inline static void
Hacl_Impl_Curve25519_Field64_Hacl_cswap2(uint64_t bit, uint64_t *p1, uint64_t *p2)
{
  uint64_t mask = (uint64_t)0U - bit;
  uint32_t i;
  for (i = (uint32_t)0U; i < (uint32_t)8U; i = i + (uint32_t)1U)
  {
    uint64_t dummy = mask & (p1[i] ^ p2[i]);
    p1[i] = p1[i] ^ dummy;
    p2[i] = p2[i] ^ dummy;
  }
}

static uint8_t
Hacl_Curve25519_64_Slow_g25519[32U] =
  {
    (uint8_t)9U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U,
    (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U,
    (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U,
    (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U,
    (uint8_t)0U, (uint8_t)0U, (uint8_t)0U, (uint8_t)0U
  };

static void
Hacl_Curve25519_64_Slow_point_add_and_double(uint64_t *q, uint64_t *p01_tmp1, uint64_t *tmp2)
{
  uint64_t *nq = p01_tmp1;
  uint64_t *nq_p1 = p01_tmp1 + (uint32_t)8U;
  uint64_t *tmp1 = p01_tmp1 + (uint32_t)16U;
  uint64_t *x1 = q;
  uint64_t *x2 = nq;
  uint64_t *z2 = nq + (uint32_t)4U;
  uint64_t *z3 = nq_p1 + (uint32_t)4U;
  uint64_t *a = tmp1;
  uint64_t *b = tmp1 + (uint32_t)4U;
  uint64_t *ab = tmp1;
  uint64_t *dc = tmp1 + (uint32_t)8U;
  uint64_t *x3;
  uint64_t *z31;
  uint64_t *d0;
  uint64_t *c0;
  uint64_t *a1;
  uint64_t *b1;
  uint64_t *d;
  uint64_t *c;
  uint64_t *ab1;
  uint64_t *dc1;
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(a, x2, z2);
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(b, x2, z2);
  x3 = nq_p1;
  z31 = nq_p1 + (uint32_t)4U;
  d0 = dc;
  c0 = dc + (uint32_t)4U;
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(c0, x3, z31);
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(d0, x3, z31);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul2(dc, dc, ab, tmp2);
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(x3, d0, c0);
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(z31, d0, c0);
  a1 = tmp1;
  b1 = tmp1 + (uint32_t)4U;
  d = tmp1 + (uint32_t)8U;
  c = tmp1 + (uint32_t)12U;
  ab1 = tmp1;
  dc1 = tmp1 + (uint32_t)8U;
  Hacl_Impl_Curve25519_Field64_Hacl_fsqr2(dc1, ab1, tmp2);
  Hacl_Impl_Curve25519_Field64_Hacl_fsqr2(nq_p1, nq_p1, tmp2);
  a1[0U] = c[0U];
  a1[1U] = c[1U];
  a1[2U] = c[2U];
  a1[3U] = c[3U];
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(c, d, c);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul1(b1, c, (uint64_t)121665U);
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(b1, b1, d);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul2(nq, dc1, ab1, tmp2);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(z3, z3, x1, tmp2);
}

static void Hacl_Curve25519_64_Slow_point_double(uint64_t *nq, uint64_t *tmp1, uint64_t *tmp2)
{
  uint64_t *x2 = nq;
  uint64_t *z2 = nq + (uint32_t)4U;
  uint64_t *a = tmp1;
  uint64_t *b = tmp1 + (uint32_t)4U;
  uint64_t *d = tmp1 + (uint32_t)8U;
  uint64_t *c = tmp1 + (uint32_t)12U;
  uint64_t *ab = tmp1;
  uint64_t *dc = tmp1 + (uint32_t)8U;
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(a, x2, z2);
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(b, x2, z2);
  Hacl_Impl_Curve25519_Field64_Hacl_fsqr2(dc, ab, tmp2);
  a[0U] = c[0U];
  a[1U] = c[1U];
  a[2U] = c[2U];
  a[3U] = c[3U];
  Hacl_Impl_Curve25519_Field64_Hacl_fsub(c, d, c);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul1(b, c, (uint64_t)121665U);
  Hacl_Impl_Curve25519_Field64_Hacl_fadd(b, b, d);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul2(nq, dc, ab, tmp2);
}

static void
Hacl_Curve25519_64_Slow_montgomery_ladder(uint64_t *out, uint8_t *key, uint64_t *init1)
{
  uint64_t tmp2[16U] = { 0U };
  uint64_t p01_tmp1_swap[33U] = { 0U };
  uint64_t *p0 = p01_tmp1_swap;
  uint64_t *p01 = p01_tmp1_swap;
  uint64_t *p03 = p01;
  uint64_t *p11 = p01 + (uint32_t)8U;
  uint64_t *x0;
  uint64_t *z0;
  uint64_t *p01_tmp1;
  uint64_t *p01_tmp11;
  uint64_t *nq10;
  uint64_t *nq_p11;
  uint64_t *swap1;
  uint64_t sw0;
  uint64_t *nq1;
  uint64_t *tmp1;
  memcpy(p11, init1, (uint32_t)8U * sizeof init1[0U]);
  x0 = p03;
  z0 = p03 + (uint32_t)4U;
  x0[0U] = (uint64_t)1U;
  x0[1U] = (uint64_t)0U;
  x0[2U] = (uint64_t)0U;
  x0[3U] = (uint64_t)0U;
  z0[0U] = (uint64_t)0U;
  z0[1U] = (uint64_t)0U;
  z0[2U] = (uint64_t)0U;
  z0[3U] = (uint64_t)0U;
  p01_tmp1 = p01_tmp1_swap;
  p01_tmp11 = p01_tmp1_swap;
  nq10 = p01_tmp1_swap;
  nq_p11 = p01_tmp1_swap + (uint32_t)8U;
  swap1 = p01_tmp1_swap + (uint32_t)32U;
  Hacl_Impl_Curve25519_Field64_Hacl_cswap2((uint64_t)1U, nq10, nq_p11);
  Hacl_Curve25519_64_Slow_point_add_and_double(init1, p01_tmp11, tmp2);
  swap1[0U] = (uint64_t)1U;
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < (uint32_t)251U; i = i + (uint32_t)1U)
    {
      uint64_t *p01_tmp12 = p01_tmp1_swap;
      uint64_t *swap2 = p01_tmp1_swap + (uint32_t)32U;
      uint64_t *nq2 = p01_tmp12;
      uint64_t *nq_p12 = p01_tmp12 + (uint32_t)8U;
      uint64_t
      bit =
        (uint64_t)(key[((uint32_t)253U - i)
        / (uint32_t)8U]
        >> ((uint32_t)253U - i) % (uint32_t)8U
        & (uint8_t)1U);
      uint64_t sw = swap2[0U] ^ bit;
      Hacl_Impl_Curve25519_Field64_Hacl_cswap2(sw, nq2, nq_p12);
      Hacl_Curve25519_64_Slow_point_add_and_double(init1, p01_tmp12, tmp2);
      swap2[0U] = bit;
    }
  }
  sw0 = swap1[0U];
  Hacl_Impl_Curve25519_Field64_Hacl_cswap2(sw0, nq10, nq_p11);
  nq1 = p01_tmp1;
  tmp1 = p01_tmp1 + (uint32_t)16U;
  Hacl_Curve25519_64_Slow_point_double(nq1, tmp1, tmp2);
  Hacl_Curve25519_64_Slow_point_double(nq1, tmp1, tmp2);
  Hacl_Curve25519_64_Slow_point_double(nq1, tmp1, tmp2);
  memcpy(out, p0, (uint32_t)8U * sizeof p0[0U]);
}

static void
Hacl_Curve25519_64_Slow_fsquare_times(uint64_t *o, uint64_t *inp, uint64_t *tmp, uint32_t n1)
{
  uint32_t i;
  Hacl_Impl_Curve25519_Field64_Hacl_fsqr(o, inp, tmp);
  for (i = (uint32_t)0U; i < n1 - (uint32_t)1U; i = i + (uint32_t)1U)
  {
    Hacl_Impl_Curve25519_Field64_Hacl_fsqr(o, o, tmp);
  }
}

static void Hacl_Curve25519_64_Slow_finv(uint64_t *o, uint64_t *i, uint64_t *tmp)
{
  uint64_t t1[16U] = { 0U };
  uint64_t *a0 = t1;
  uint64_t *b = t1 + (uint32_t)4U;
  uint64_t *c = t1 + (uint32_t)8U;
  uint64_t *t00 = t1 + (uint32_t)12U;
  uint64_t *tmp1 = tmp;
  uint64_t *a;
  uint64_t *t0;
  Hacl_Curve25519_64_Slow_fsquare_times(a0, i, tmp1, (uint32_t)1U);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, a0, tmp1, (uint32_t)2U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(b, t00, i, tmp);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(a0, b, a0, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, a0, tmp1, (uint32_t)1U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(b, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, b, tmp1, (uint32_t)5U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(b, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, b, tmp1, (uint32_t)10U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(c, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, c, tmp1, (uint32_t)20U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(t00, t00, c, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, t00, tmp1, (uint32_t)10U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(b, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, b, tmp1, (uint32_t)50U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(c, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, c, tmp1, (uint32_t)100U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(t00, t00, c, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, t00, tmp1, (uint32_t)50U);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(t00, t00, b, tmp);
  Hacl_Curve25519_64_Slow_fsquare_times(t00, t00, tmp1, (uint32_t)5U);
  a = t1;
  t0 = t1 + (uint32_t)12U;
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(o, t0, a, tmp);
}

static void Hacl_Curve25519_64_Slow_store_felem(uint64_t *b, uint64_t *f)
{
  uint64_t f30 = f[3U];
  uint64_t top_bit0 = f30 >> (uint32_t)63U;
  uint64_t carry0;
  uint64_t f31;
  uint64_t top_bit;
  uint64_t carry;
  uint64_t f0;
  uint64_t f1;
  uint64_t f2;
  uint64_t f3;
  uint64_t m0;
  uint64_t m1;
  uint64_t m2;
  uint64_t m3;
  uint64_t mask;
  uint64_t f0_;
  uint64_t f1_;
  uint64_t f2_;
  uint64_t f3_;
  uint64_t o0;
  uint64_t o1;
  uint64_t o2;
  uint64_t o3;
  f[3U] = f30 & (uint64_t)0x7fffffffffffffffU;
  carry0 = Hacl_Impl_Curve25519_Field64_Hacl_add1(f, f, (uint64_t)19U * top_bit0);
  f31 = f[3U];
  top_bit = f31 >> (uint32_t)63U;
  f[3U] = f31 & (uint64_t)0x7fffffffffffffffU;
  carry = Hacl_Impl_Curve25519_Field64_Hacl_add1(f, f, (uint64_t)19U * top_bit);
  f0 = f[0U];
  f1 = f[1U];
  f2 = f[2U];
  f3 = f[3U];
  m0 = FStar_UInt64_gte_mask(f0, (uint64_t)0xffffffffffffffedU);
  m1 = FStar_UInt64_eq_mask(f1, (uint64_t)0xffffffffffffffffU);
  m2 = FStar_UInt64_eq_mask(f2, (uint64_t)0xffffffffffffffffU);
  m3 = FStar_UInt64_eq_mask(f3, (uint64_t)0x7fffffffffffffffU);
  mask = ((m0 & m1) & m2) & m3;
  f0_ = f0 - (mask & (uint64_t)0xffffffffffffffedU);
  f1_ = f1 - (mask & (uint64_t)0xffffffffffffffffU);
  f2_ = f2 - (mask & (uint64_t)0xffffffffffffffffU);
  f3_ = f3 - (mask & (uint64_t)0x7fffffffffffffffU);
  o0 = f0_;
  o1 = f1_;
  o2 = f2_;
  o3 = f3_;
  b[0U] = o0;
  b[1U] = o1;
  b[2U] = o2;
  b[3U] = o3;
}

static void Hacl_Curve25519_64_Slow_encode_point(uint8_t *o, uint64_t *i)
{
  uint64_t *x = i;
  uint64_t *z = i + (uint32_t)4U;
  uint64_t tmp[4U] = { 0U };
  uint64_t u64s[4U] = { 0U };
  uint64_t tmp_w[16U] = { 0U };
  Hacl_Curve25519_64_Slow_finv(tmp, z, tmp_w);
  Hacl_Impl_Curve25519_Field64_Hacl_fmul(tmp, tmp, x, tmp_w);
  Hacl_Curve25519_64_Slow_store_felem(u64s, tmp);
  {
    uint32_t i0;
    for (i0 = (uint32_t)0U; i0 < (uint32_t)4U; i0 = i0 + (uint32_t)1U)
    {
      store64_le(o + i0 * (uint32_t)8U, u64s[i0]);
    }
  }
}

void Hacl_Curve25519_64_Slow_scalarmult(uint8_t *out, uint8_t *priv, uint8_t *pub)
{
  uint64_t init1[8U] = { 0U };
  uint64_t tmp[4U] = { 0U };
  uint64_t tmp3;
  uint64_t *x;
  uint64_t *z;
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < (uint32_t)4U; i = i + (uint32_t)1U)
    {
      uint64_t *os = tmp;
      uint8_t *bj = pub + i * (uint32_t)8U;
      uint64_t u = load64_le(bj);
      uint64_t r = u;
      uint64_t x0 = r;
      os[i] = x0;
    }
  }
  tmp3 = tmp[3U];
  tmp[3U] = tmp3 & (uint64_t)0x7fffffffffffffffU;
  x = init1;
  z = init1 + (uint32_t)4U;
  z[0U] = (uint64_t)1U;
  z[1U] = (uint64_t)0U;
  z[2U] = (uint64_t)0U;
  z[3U] = (uint64_t)0U;
  x[0U] = tmp[0U];
  x[1U] = tmp[1U];
  x[2U] = tmp[2U];
  x[3U] = tmp[3U];
  Hacl_Curve25519_64_Slow_montgomery_ladder(init1, priv, init1);
  Hacl_Curve25519_64_Slow_encode_point(out, init1);
}

void Hacl_Curve25519_64_Slow_secret_to_public(uint8_t *pub, uint8_t *priv)
{
  uint8_t basepoint[32U] = { 0U };
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < (uint32_t)32U; i = i + (uint32_t)1U)
    {
      uint8_t *os = basepoint;
      uint8_t x = Hacl_Curve25519_64_Slow_g25519[i];
      os[i] = x;
    }
  }
  Hacl_Curve25519_64_Slow_scalarmult(pub, priv, basepoint);
}

bool Hacl_Curve25519_64_Slow_ecdh(uint8_t *out, uint8_t *priv, uint8_t *pub)
{
  uint8_t zeros1[32U] = { 0U };
  Hacl_Curve25519_64_Slow_scalarmult(out, priv, pub);
  {
    uint8_t res = (uint8_t)255U;
    uint8_t z;
    bool r;
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)32U; i = i + (uint32_t)1U)
      {
        uint8_t uu____0 = FStar_UInt8_eq_mask(out[i], zeros1[i]);
        res = uu____0 & res;
      }
    }
    z = res;
    r = z == (uint8_t)255U;
    return !r;
  }
}

