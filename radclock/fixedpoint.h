/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
 *
 * This file is part of the radclock program.
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef _RAD_FIXEDPOINT_H
#define _RAD_FIXEDPOINT_H


/**
 * -------------------------------------------
 * Code for working out integer approximations
 *
 * Basic idea:
 * We add a delta vcounter converted into seconds to a reference time value
 * computed earlier. Because we have to use implicit fixed point arithmetic, we
 * need to multiply the floating point values and then shift the decimal dot as
 * far as possible. This is done by power of 2 multiplication (i.e. binary shift)
 *
 * Here is a brief overview of the complete process with breakdown of loss of
 * accuracy in the worst case for the final timestamp created (the worst can
 * being when the interval between the reference and current counter value is
 * large.
 *
 * ------------
 * In userland:
 * Take reference time and needed values converted to fixed point and pass them
 * to the kernel.
 * time_ref is shifted to the left by TIM_SHIFT bits 
 * 		-> loss:  1/2^TIME_SHIFT
 * phat is shifted to the left by PHAT_SHIFT bits 
 * 		-> loss:  1/2^PHAT_SHIFT
 *
 * --------------
 * In the kernel: 
 * 1) Compute the difference between reference and current vcounter
 * 2) If the difference is over countdiff_maxbits, will overflow, emit warning 
 * 3) Multiply the countdiff by the integer version of phat	
 * 		-> loss:  1/2^PHAT_SHIFT * MAX_COUNTER_BITS
 * 4) Shift this value to the right to align it with time_int. This corresponds
 *    to a right shift of (PHAT_SHIFT - TIME_SHIFT) 
 *    	-> loss:  1/2^TIME_SHIFT + (1/2^PHAT_SHIFT * MAX_COUNTER_BITS)
 * 5) Add this value to time_int
 * 		-> loss:  1/2^TIME_SHIFT + (1/2^TIME_SHIFT) + (1/2^PHAT_SHIFT * MAX_COUNTER_BITS)
 * 6) Right shift it by TIME_SHIFT to get seconds and store in timeval
 * 7) Subtract seconds, multiply by 100000, right shift by TIME_SHIFT to get microseconds
 * 		-> loss: 1/1000000 + 2 * (1/2^TIME_SHIFT) + (1/2^PHAT_SHIFT * MAX_COUNTER_BITS)
 *
 * Worst case Loss of accuracy: 
 * 			1/1000000 + 2*(1/2^TIME_SHIFT) + (1/2^PHAT_SHIFT * MAX_COUNTER_BITS)
 *
 *
 * -----------
 * TIME_SHIFT.
 * That's the simple case, since the time reference is involved in the addition
 * only. We want to have a time reference with has many significant digits as
 * possible. So we want to left shift the time reference as much as possible.
 * Constraint to the left is to not start getting rid of bits representing
 * seconds since 1970.  Idea is to count number of bits needed to hold the
 * current seconds of the time ref (+1 for next bit flipping during operation)
 * and subtract that number to the 64 bit container.  See
 * calculate_time_shift().
 *
 * -----------
 * PHAT_SHIFT.
 * A bit trickier since it used when multiplying the counter's delta with phat
 * as an int. The constraint is:
 * 		bitcount(phat_int) + bitcount(countdiff) < 64 bits
 *
 * We cannot directly control the number of bits of the countdiff except by
 * updating the kernel often enough. So we can pick up a value MAX_COUNTDIFF
 * and we will have to update faster than that.
 * Then we work out phat_shift (again with a 1 bit guard band)
 * 		bitcount(phat_int) = 64 - bitcount(MAX_COUNTDIFF) - 1
 * phat being a floating point, the shift actually correspond to a
 * multiplication. So if phat = 1, phat_int = phat * (1LL << bitcount(phat_int))
 * exactly fits in the number of bits we allocate it to respect the constraint. 
 * But phat is way smaller than 1, so we would loose a lot of significant digits.
 * So multiply by 1/phat to gain way more digits.
 *
 * That gives us:
 * 		phat_int = phat * phat_shift
 * with
 * 		phat_shift = (1LL << bitcount(phat_int)) * 1/phat
 *
 * phat_shift gets smaller as the countdiff increases, leading to a higher loss
 * of precision. With a predicted worse case of a 5Ghz TSC, a quick simulation
 * shows a worse case loss of precision of 0.1 [musec] with a MAX_COUNTDIFF of 30
 * seconds. For the same MAX_COUNTDIFF, HPET and ACPI offer sub-nano loss of
 * precision due to phat_shift. 
 * NOTE: to be below the nanosec precision loss level with a 5Ghz counter, we should
 * define a MAX_COUNTDIFF < 2 [sec], quite fast updates then.
 *
 * Of course we will attempt to update faster than COUNTERDIFF_MAX in case some
 * updates are lost in limbo.
 */

#define COUNTERDIFF_MAX 	30	// Maximum time in between 2 kernel updates in [sec]

/* Historic old static parameters:
 * #define TIME_SHIFT			32	// Shift factor for time_ref
 * #define PHAT_SHIFT			56	// Shift factor for phat
 * #define COUNTERDIFF_MAX_BITS	33	// Max number of bits for counter difference
 */


int update_kernel_fixed(struct radclock *handle);


#endif
