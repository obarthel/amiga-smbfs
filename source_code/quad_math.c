/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2018 by Olaf `Olsen' Barthel <obarthel -at- gmx -dot- net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _SMBFS_H
#include "smbfs.h"
#endif /* _SMBFS_H */

/****************************************************************************/

/* This function comes from Harry S. Warren, Jr.'s book "Hacker's delight". */
static INLINE int
carry(ULONG x, ULONG y)
{
	int result;
	ULONG z;

	z = (x & y) | ((x | y) & ~(x + y));

	result = ((LONG)z) < 0 ? 1 : 0;

	return(result);
}

/****************************************************************************/

/* This function comes from Harry S. Warren, Jr.'s book "Hacker's delight".
 * Computes the high-order half of the 64-bit product, unsigned. Derived
 * from Knuth's Algorithm M.
 */
static ULONG mulhu (ULONG u, ULONG v)
{
	ULONG u0, u1, v0, v1, w0, w1, w2, t;

	u0 = u & 0xFFFF;
	u1 = u >> 16;

	v0 = v & 0xFFFF;
	v1 = v >> 16;

	w0 = u0 * v0;

	t = u1 * v0 + (w0 >> 16);

	w1 = t & 0xFFFF;
	w2 = t >> 16;
	w1 = u0 * v1 + w1;

	return u1 * v1 + w2 + (w1 >> 16);
}

/* Multiply two 32 bit numbers, yielding a 64 bit result value. */
void
multiply_32_by_32_to_64(ULONG ab,ULONG cd,QUAD * product)
{
	product->High	= mulhu(ab,cd);
	product->Low	= ab * cd; 
}

/* Multiply an unsigned 64 bit quantity by a 32 bit quantity, yielding a 64
 * bit product. Returns the most significant component of the product, which
 * is effectively the 32 bit overflow from the 96 bit product.
 */
ULONG
multiply_64_by_32_to_64(const QUAD * const abcd,ULONG ef,QUAD * abcdef)
{
	QUAD cdef;
	QUAD abef;
	ULONG ab,cd;

	/* Split the factors so that the following is true:
	 *
	 * abcd = (ab * 65536 * 65536) + cd;
	 */
	ab = abcd->High;
	cd = abcd->Low;

	/* We need to calculate the following:
	 *
	 * abcd * ef = (ab * 65536 * 65536 + cd) * ef
	 *           = (ab * 65536 * 65536) * ef + cd * ef
	 *           = (abef) * 65536 * 65536 + cdef
	 */
	multiply_32_by_32_to_64(cd,ef,&cdef);
	multiply_32_by_32_to_64(ab,ef,&abef);

	/* Let's put it all together as: (cd+ef) * 65536 * 65536 + ef. */
	abcdef->Low		= cdef.Low;
	abcdef->High	= abef.Low + cdef.High;

	return(abef.High);
}

/****************************************************************************/

/* Divide a 64 bit integer by a 32 bit integer, filling in a 64 bit quotient
 * and returning a 32 bit remainder.
 */
ULONG
divide_64_by_32(const QUAD * const dividend,ULONG divisor,QUAD * quotient)
{
	QUAD dividend_cdef = (*dividend);
	ULONG dividend_ab = 0;
	int i;

	quotient->High = quotient->Low = 0;

	for(i = 0 ; i < 64 ; i++)
	{
		/* Shift the quotient left by one bit. */
		quotient->High = (quotient->High << 1);

		if((quotient->Low & 0x80000000UL) != 0)
			quotient->High |= 1;

		quotient->Low = (quotient->Low << 1);

		/* Shift the dividend left by one bit. We start
		 * with the most significant 32 bit portion.
		 */
		dividend_ab = (dividend_ab << 1);

		if((dividend_cdef.High & 0x80000000UL) != 0)
			dividend_ab |= 1;

		/* Now for the middle 32 bit portion. */
		dividend_cdef.High = (dividend_cdef.High << 1);

		if((dividend_cdef.Low & 0x80000000UL) != 0)
			dividend_cdef.High |= 1;

		/* Finally, the least significant portion. */
		dividend_cdef.Low = (dividend_cdef.Low << 1);

		/* Does the divisor actually divide the dividend? */
		if(dividend_ab >= divisor)
		{
			dividend_ab -= divisor;

			/* We could divide the divisor. Keep track of
			 * this and take care of an overflow condition.
			 */
			quotient->Low++;
			if(quotient->Low == 0)
				quotient->High++;
		}
	}

	return(dividend_ab);
}

/****************************************************************************/

/* Add an unsigned 32 bit quantity to a 64 bit quantity, yielding a
 * 64 bit sum.
 */
ULONG
add_64_plus_32_to_64(const QUAD * const a,ULONG b,QUAD * ab)
{
	QUAD b_quad;

	b_quad.Low	= b;
	b_quad.High	= 0;

	return(add_64_plus_64_to_64(a,&b_quad,ab));
}

/****************************************************************************/

/* Add an unsigned 64 bit quantity to a 64 bit quantity, yielding a
 * 64 bit sum.
 */
ULONG
add_64_plus_64_to_64(const QUAD * const a,const QUAD * const b,QUAD * ab)
{
	ULONG low,high,overflow = 0;

	/* Add the first summand to the least significant
	 * component of the second summand and check for
	 * overflow.
	 */
	low		= a->Low + b->Low;
	high	= carry(a->Low, b->Low);

	/* Put it all together. */
	ab->Low = low;

	/* Add the most significant components and check
	 * for overflow.
	 */
	overflow += carry(high, a->High);
	high += a->High;

	overflow += carry(high, b->High);
	ab->High = high + b->High;

	return(overflow);
}

/****************************************************************************/

/* Subtract a 64 bit integer from another 64 bit integer, producing a
 * 64 bit integer difference, returning a 32 bit integer that indicates
 * whether or not an underflow occured.
 */
ULONG
subtract_64_from_64_to_64(const QUAD * const minuend,const QUAD * const subtrahend,QUAD * difference)
{
	QUAD extended_minuend;

	/* We may have to borrow if the minuend is less than the
	 * subtrahend, so we set up a local variable to track
	 * any underflow this might produce.
	 */
	extended_minuend.High	= 0;
	extended_minuend.Low	= minuend->High;

	/* First step: take care of the least significant word. If
	 * that produces a local underflow, borrow from the most
	 * significant word.
	 */
	if(minuend->Low < subtrahend->Low)
	{
		/* Borrow, and if there's nothing to be borrowed,
		 * remember that we had an underflow.
		 */
		if(extended_minuend.Low-- == 0)
			extended_minuend.High--;
	}

	difference->Low = minuend->Low - subtrahend->Low;

	/* Second step: take care of the most significant word. If
	 * that produces a local underflow, remember that.
	 */
	if(extended_minuend.Low < subtrahend->High)
		extended_minuend.High--;

	difference->High = extended_minuend.Low - subtrahend->High;

	/* Return the underflow, if any. */
	return(extended_minuend.High);
}

/****************************************************************************/

/* Compare two unsigned 64 bit integers in the manner of strcmp(). */
int
compare_64_to_64(const QUAD * const a,const QUAD * const b)
{
	int result;

	if(a->High < b->High)
	{
		result = -1;
	}
	else if (a->High == b->High)
	{
		if (a->Low < b->Low)
			result = -1;
		else if (a->Low == b->Low)
			result = 0;
		else
			result = 1;
	}
	else
	{
		result = 1;
	}

	return(result);
}
