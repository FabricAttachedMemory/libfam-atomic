#ifndef _URCU_ARCH_X86_H
#define _URCU_ARCH_X86_H

/*
 * arch_x86.h: trivial definitions for the x86 architecture.
 *
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "compiler.h"
#include "rcu_config.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifdef __x86_64__

#define CAA_CACHE_LINE_SIZE	128

#define cmm_mb()    asm volatile("mfence":::"memory")
#define cmm_rmb()   asm volatile("lfence":::"memory")
#define cmm_wmb()   asm volatile("sfence"::: "memory")

#define caa_cpu_relax()	asm volatile("rep; nop" : : : "memory");

#define rdtscll(val)							  \
	do {						  		  \
	     unsigned int __a, __d;					  \
	     asm volatile("rdtsc" : "=a" (__a), "=d" (__d));		  \
	     (val) = ((unsigned long long)__a)				  \
			| (((unsigned long long)__d) << 32);		  \
	} while(0)

typedef unsigned long long cycles_t;

static inline cycles_t caa_get_cycles(void)
{
        cycles_t ret = 0;

        rdtscll(ret);
        return ret;
}

#elif __aarch64__

#define CAA_CACHE_LINE_SIZE	256

#define cmm_mb()	asm volatile("dmb ish":::"memory")
#define cmm_rmb()	asm volatile("dmb ishld":::"memory")
#define cmm_wmb()	asm volatile("dmb ishst":::"memory")

#include <stdlib.h>
#include <sys/time.h>

typedef unsigned long long cycles_t;

static inline cycles_t caa_get_cycles (void)
{
	cycles_t thetime;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return 0;
	thetime = ((cycles_t)tv.tv_sec) * 1000000ULL + ((cycles_t)tv.tv_usec);
	return (cycles_t)thetime;
}

#else

arch_not_supported();

#endif


#ifdef __cplusplus 
}
#endif

#include "arch_generic.h"

#endif /* _URCU_ARCH_X86_H */
