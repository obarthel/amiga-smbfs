/*
 * $Id: quad_math.c,v 1.1 2005-05-27 09:48:26 obarthel Exp $
 *
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2005 by Olaf `Olsen' Barthel <olsen@sourcery.han.de>
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

#ifndef _QUAD_MATH_H
#include "quad_math.h"
#endif /* _QUAD_MATH_H */

/****************************************************************************/

/* Multiply two unsigned 32 bit quantities, yielding a 64 bit product. */
void
multiply_32_by_32_to_64(ULONG ab,ULONG cd,QUAD * abcd)
{
	ULONG a,b,c,d,ad_plus_bc_low,ad_plus_bc_high,bc,bd,ad;

	/* Split the factors again so that the following is true:
	 *
	 * ab = (a * 65536) + b
	 * cd = (c * 65536) + d
	 */
	a = (ab >> 16);
	b = ab & 0xFFFF;
	c = (cd >> 16);
	d = cd & 0xFFFF;

	/* We need to calculate the following product:
	 *
	 * ab * cd = (a * 65536 + b) * cd
	 *         = a * 65536 * cd + b * cd
	 *         = a * 65536 * (c * 65536 + d) + b * (c * 65536 + d)
	 *         = a * 65536 * c * 65536 + a * 65536 * d + b + c * 65536 + b * d
	 *         = ac * 65536 * 65536 + ad * 65536 + bc * 65536 * bd
	 *         = ac * 65536 * 65536 + (ad + bc) * 65536 + bc
	 */
	ad = a * d;
	bc = b * c;
	bd = b * d;

	/* We can put the most and least significant components of the
	 * product right into the result buffer.
	 */
	abcd->High	= a * c;
	abcd->Low	= bd;

	/* Add ad and bc and check if there was an overflow. */
	ad_plus_bc_low	= ad + bc;
	ad_plus_bc_high	= (ad_plus_bc_low < ad) ? 1 : 0;

	/* Add the lower 16 bits of the ad+bc sum to the least
	 * significant component of the result buffer and
	 * check for overflow.
	 */
	abcd->Low += (ad_plus_bc_low << 16);
	if(abcd->Low < bd)
		abcd->High++;

	/* Add the upper 16 bits of the ad+bc sum to the most
	 * significant component of the result buffer. Add
	 * the overflow bit of the ad+bc sum, too.
	 */
	abcd->High += ((ad_plus_bc_low >> 16) & 0xFFFF) + (ad_plus_bc_high << 16);
}

/****************************************************************************/

/* Divide a 64 bit integer by a 32 bit integer, filling in a 64 bit quotient
   and returning a 32 bit remainder. */
ULONG
divide_64_by_32(QUAD * dividend,ULONG divisor,QUAD * quotient)
{
	QUAD dividend_cdef = (*dividend);
	ULONG dividend_ab = 0;
	LONG i;

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

/* Subtract a 64 bit integer from another 64 bit integer, producing a
   64 bit integer difference, returning a 32 bit integer that indicates
   whether or not an underflow occured. */
ULONG
subtract_64_from_64_to_64(const QUAD * const minuend,const QUAD * const subtrahend,QUAD * difference)
{
	QUAD extended_minuend;

	/* We may have to borrow if the minuend is less than the
	   subtrahend, so we set up a local variable to track
	   any underflow this might produce. */
	extended_minuend.High	= 0;
	extended_minuend.Low	= minuend->High;

	/* First step: take care of the least significant word. If
	   that produces a local underflow, borrow from the most
	   significant word. */
	if(minuend->Low < subtrahend->Low)
	{
		/* Borrow, and if there's nothing to be borrowed,
		   remember that we had an underflow. */
		if(extended_minuend.Low-- == 0)
			extended_minuend.High--;
	}

	difference->Low = minuend->Low - subtrahend->Low;

	/* Second step: take care of the most significant word. If
	   that produces a local underflow, remember that. */
	if(extended_minuend.Low < subtrahend->High)
		extended_minuend.High--;

	difference->High = extended_minuend.Low - subtrahend->High;

	/* Return the underflow, if any. */
	return(extended_minuend.High);
}
