/*
 * Copyright © 2015, Hewlett Packard Enterprise Development LP
 *
 * Author: Jason Low <jason.low2@hpe.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include "fam_atomic.h"
#include "rcu-rbtree/urcu-bp.h"
#include "rcu-rbtree/rcurbtree.h"

#define LOCK_PREFIX_HERE                  \
	".pushsection .smp_locks,\"a\"\n" \
	".balign 4\n"                     \
	".long 671f - .\n"                \
	".popsection\n"                   \
	"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define debug(message)

#define u32 unsigned int
#define u64 unsigned long long

void fam_atomic_compare_exchange_wrong_size(void);
void fam_atomic_xadd_wrong_size(void);
void fam_atomic_xchg_wrong_size(void);
void store_release_wrong_size(void);
void fam_atomic_arch_not_supported(void);

#ifdef __x86_64__

#define store_release(ptr, val) 		\
do {						\
	__asm__ __volatile__("": : :"memory");	\
	ACCESS_ONCE(*ptr) =  val;		\
} while (0);

#define __x86_raw_cmpxchg(ptr, old, new, size, lock)		\
({								\
	__typeof__(*(ptr)) __ret;				\
	__typeof__(*(ptr)) __old = (old);			\
	__typeof__(*(ptr)) __new = (new);			\
	switch (size) {						\
	case 4:							\
	{							\
		volatile u32 *__ptr = (volatile u32 *)(ptr);	\
		asm volatile(lock "cmpxchgl %2,%1"		\
			     : "=a" (__ret), "+m" (*__ptr)	\
			     : "r" (__new), "0" (__old)		\
			     : "memory");			\
		break;						\
	}							\
	case 8:							\
	{							\
		volatile u64 *__ptr = (volatile u64 *)(ptr);	\
		asm volatile(lock "cmpxchgq %2,%1"		\
			     : "=a" (__ret), "+m" (*__ptr)	\
			     : "r" (__new), "0" (__old)		\
			     : "memory");			\
		break;						\
	}							\
	default:						\
		fam_atomic_compare_exchange_wrong_size();	\
	}							\
	__ret;							\
})

#define __x86_cmpxchg(ptr, old, new, size) \
	__x86_raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)

#define __x86_xchg_op(ptr, arg, op, lock)				\
	({								\
		__typeof__ (*(ptr)) __ret = (arg);			\
		switch (sizeof(*(ptr))) {				\
		case 4:							\
			asm volatile (lock #op "l %0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case 8:							\
			asm volatile (lock #op "q %q0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		default:						\
		       fam_atomic_ ## op ## _wrong_size();		\
		}							\
		__ret;							\
	})

#define __x86_xadd(ptr, inc, lock)	__x86_xchg_op((ptr), (inc), xadd, lock)

#define __x86_cmpxchg16(pfx, p1, p2, o1, o2, n1, n2)			\
({									\
	bool __ret;							\
	__typeof__(*(p1)) __old1 = (o1), __new1 = (n1);			\
	__typeof__(*(p2)) __old2 = (o2), __new2 = (n2);			\
	asm volatile(pfx "cmpxchg%c4b %2; sete %0"			\
		     : "=a" (__ret), "+d" (__old2),			\
		       "+m" (*(p1)), "+m" (*(p2))			\
		     : "i" (2 * sizeof(long)), "a" (__old1),		\
		       "b" (__new1), "c" (__new2));			\
	__ret;								\
})

#define xchg(ptr, v)		__x86_xchg_op((ptr), (v), xchg, "")
#define xadd(ptr, inc)		__x86_xadd((ptr), (inc), LOCK_PREFIX)
#define cmpxchg(ptr, old, new)	__x86_cmpxchg(ptr, old, new, sizeof(*(ptr)))
#define cmpxchg16(p1, p2, o1, o2, n1, n2) \
	__x86_cmpxchg16(LOCK_PREFIX, p1, p2, o1, o2, n1, n2)

#elif __aarch64__

#define store_release(ptr, val)                                         \
do {                                                                    \
        switch (sizeof(*ptr)) {                                         \
        case 4:                                                         \
                asm volatile ("stlr %w1, %0"                            \
                                : "=Q" (*ptr) : "r" (val) : "memory");  \
                break;                                                  \
        case 8:                                                         \
                asm volatile ("stlr %1, %0"                             \
                                : "=Q" (*ptr) : "r" (val) : "memory");  \
                break;                                                  \
	default:							\
		store_release_wrong_size();				\
        }                                                               \
} while (0)

static inline int arm_atomic_add_return(void *ptr, int inc)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_add_return\n"
"1:     ldxr    %w0, %2\n"
"       add     %w0, %w0, %w3\n"
"       stlxr   %w1, %w0, %2\n"
"       cbnz    %w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (*((u32 *)ptr))
	: "Ir" (inc)
	: "memory");

	__asm__ __volatile__ ("dsb ish" : : : "memory");
				
	return result;
}

static inline long arm_atomic64_add_return(void *ptr, long inc)          
{                                                                       
	long result;                                                    
	unsigned long tmp;                                             
				                                        
	asm volatile("// atomic64_add_return\n"                         
"1:     ldxr    %0, %2\n"                                               
"       add     %0, %0, %3\n"                                           
"       stlxr   %w1, %0, %2\n"                                          
"       cbnz    %w1, 1b"                                                
	: "=&r" (result), "=&r" (tmp), "+Q" (*((u64 *)ptr))                    
	: "Ir" (inc)                                                      
	: "memory");                                                    
				                                        
	__asm__ __volatile__ ("dsb ish" : : : "memory");
	return result;                                                  
}

#define arm_xadd(ptr, inc)						\
	({								\
		__typeof__ (*(ptr)) __ret;				\
		switch(sizeof(*(ptr))) {				\
		case 4:							\
			__ret = arm_atomic_add_return(ptr, inc);	\
			break;						\
		case 8:							\
			__ret = arm_atomic64_add_return(ptr, inc);	\
			break;						\
		default:						\
			fam_atomic_xadd_wrong_size();			\
		}							\
		(__ret - inc);						\
	})

static inline unsigned long __arm_cmpxchg(volatile void *ptr, unsigned long old,
				      unsigned long new, int size)
{
	unsigned long oldval = 0, res;

	switch (size) {
	case 4:
		do {
			asm volatile("// __cmpxchg4\n"
			"       ldxr    %w1, %2\n"
			"       mov     %w0, #0\n"
			"       cmp     %w1, %w3\n"
			"       b.ne    1f\n"
			"       stxr    %w0, %w4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(u32 *)ptr)
				: "Ir" (old), "r" (new)
				: "cc");
		} while (res);
		break;

	case 8:
		do {
			asm volatile("// __cmpxchg8\n"
			"       ldxr    %1, %2\n"
			"       mov     %w0, #0\n"
			"       cmp     %1, %3\n"
			"       b.ne    1f\n"
			"       stxr    %w0, %4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(u64 *)ptr)
				: "Ir" (old), "r" (new)
				: "cc");
		} while (res);
		break;

	default:
		break;
	}

	return oldval;
}

static inline unsigned long __arm_cmpxchg_mb(volatile void *ptr, unsigned long old,
				         unsigned long new, int size)
{
	unsigned long ret;

	__asm__ __volatile__ ("dsb ish" : : : "memory");
	ret = __arm_cmpxchg(ptr, old, new, size);
	__asm__ __volatile__ ("dsb ish" : : : "memory");

	return ret;
}

#define arm_cmpxchg(ptr, o, n) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__arm_cmpxchg_mb((ptr), (unsigned long)(o), (unsigned long)(n), \
			     sizeof(*(ptr))); \
	__ret; \
})

static inline unsigned long __arm_xchg(unsigned long x, volatile void *ptr, int size)
{
	unsigned long ret, tmp;

	switch (size) {
	case 4:
		asm volatile("//        __xchg4\n"
		"1:     ldxr    %w0, %2\n"
		"       stlxr   %w1, %w3, %2\n"
		"       cbnz    %w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u32 *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 8:
		asm volatile("//        __xchg8\n"
		"1:     ldxr    %0, %2\n"
		"       stlxr   %w1, %3, %2\n"
		"       cbnz    %w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u64 *)ptr)
			: "r" (x)
			: "memory");
		break;
	default:
	       	break;
	}

	__asm__ __volatile__ ("dsb ish" : : : "memory");
	return ret;
}

#define arm_xchg(ptr,x) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__arm_xchg((unsigned long)(x), (ptr), sizeof(*(ptr))); \
	__ret; \
})

static inline int __arm_cmpxchg16(volatile void *ptr1, volatile void *ptr2,
		unsigned long old1, unsigned long old2,
		unsigned long new1, unsigned long new2, int size)
{
	unsigned long loop, lost;

	switch (size) {
	case 8:
		do {
			asm volatile("// __cmpxchg_double8\n"
			"       ldxp    %0, %1, %2\n"
			"       eor     %0, %0, %3\n"
			"       eor     %1, %1, %4\n"
			"       orr     %1, %0, %1\n"
			"       mov     %w0, #0\n"
			"       cbnz    %1, 1f\n"
			"       stxp    %w0, %5, %6, %2\n"
			"1:\n"
				: "=&r"(loop), "=&r"(lost), "+Q" (*(u64 *)ptr1)
				: "r" (old1), "r"(old2), "r"(new1), "r"(new2));
		} while (loop);
		break;
	default:
		break;
	}

	return !lost;
}

static inline int __arm_cmpxchg16_mb(volatile void *ptr1, volatile void *ptr2,
		        unsigned long old1, unsigned long old2,
		        unsigned long new1, unsigned long new2, int size)
{
	int ret;

	__asm__ __volatile__ ("dsb ish" : : : "memory");
	ret = __arm_cmpxchg16(ptr1, ptr2, old1, old2, new1, new2, size);
	__asm__ __volatile__ ("dsb ish" : : : "memory");

	return ret;
}

#define arm_cmpxchg16(ptr1, ptr2, o1, o2, n1, n2) \
({\
	int __ret;\
	__ret = __arm_cmpxchg16_mb((ptr1), (ptr2), (unsigned long)(o1), \
		        (unsigned long)(o2), (unsigned long)(n1), \
		        (unsigned long)(n2), sizeof(*(ptr1)));\
	__ret; \
})

#define xadd(ptr, inc)				arm_xadd(ptr, inc) 
#define xchg(ptr, val)				arm_xchg(ptr, val)
#define cmpxchg(ptr, o, n)			arm_cmpxchg(ptr, o, n)
#define cmpxchg16(ptr1, ptr2, o1, o2, n1, n2)	arm_cmpxchg16(ptr1, ptr2, o1, o2, n1, n2)

#else

fam_atomic_arch_not_supported();

#endif

static inline void ioctl_4(struct fam_atomic_args_32 *args, unsigned int opt)
{
	int32_t *atomic = (int32_t *)args->offset;
	int32_t *result_ptr = &args->p32_0;
	int32_t prev;

	switch (opt) {
	case FAM_ATOMIC_32_FETCH_AND_ADD:
		prev = xadd(atomic, args->p32_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_32_SWAP:
		prev = xchg(atomic, args->p32_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_32_COMPARE_AND_STORE:
		prev = cmpxchg(atomic, args->p32_0, args->p32_1);
		*result_ptr = prev;
		break;
	}
}

static inline void ioctl_8(struct fam_atomic_args_64 *args, unsigned int opt)
{
	int64_t *atomic = (int64_t *)args->offset;
	int64_t *result_ptr = &args->p64_0;
	int64_t prev;

	switch (opt) {
	case FAM_ATOMIC_64_FETCH_AND_ADD:
		prev = xadd(atomic, args->p64_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_64_SWAP:
		prev = xchg(atomic, args->p64_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_64_COMPARE_AND_STORE:
		prev = cmpxchg(atomic, args->p64_0, args->p64_1);
		*result_ptr = prev;
		break;
	}
}

static inline void ioctl_16(struct fam_atomic_args_128 *args, unsigned int opt)
{
	int64_t *address1 = (int64_t *)args->offset;
	int64_t *address2 = (int64_t *)((int64_t)address1 + sizeof(int64_t));
	int64_t *result1 = &(args->p128_0[0]);
	int64_t *result2 = &(args->p128_0[1]);
	bool ret;
	int64_t old[2];

	switch(opt) {
	case FAM_ATOMIC_128_SWAP:
		for (;;) {
			old[0] = xadd(address1, 0);
			old[1] = xadd(address2, 0);

			ret = cmpxchg16(address1, address2,
					old[0], old[1],
					args->p128_0[0], args->p128_0[1]);

			if (ret) {
				*result1 = old[0];
				*result2 = old[1];
				break;
			}

		}
		break;

	case FAM_ATOMIC_128_COMPARE_AND_STORE:
		for (;;) {
			ret = cmpxchg16(address1, address2,
					args->p128_0[0], args->p128_0[1],
					args->p128_1[0], args->p128_1[1]);

			if (ret) {
				*result1 = args->p128_0[0];
				*result2 = args->p128_0[1];
				break;
			} else {
				/*
				 * cmpxchg16 returned false. Sample the atomic
				 * values to obtain the "old" values, and verify
				 * they do not match the compare values so that
				 * users can correctly check that the operation
				 * did not succeed. Otherwise, retry the operation.
				 */
				old[0] = xadd(address1, 0);
				old[1] = xadd(address2, 0);

				if (old[0] != args->p128_0[0] ||
				    old[1] != args->p128_0[1]) {
					*result1 = old[0];
					*result2 = old[1];
					break;
				}
			}

		}
		break;

	case FAM_ATOMIC_128_READ:
		for (;;) {
			old[0] = xadd(address1, 0);
			old[1] = xadd(address2, 0);

			ret = cmpxchg16(address1, address2,
					old[0], old[1], old[0], old[1]);

			if (ret) {
				*result1 = old[0];
				*result2 = old[1];
				break;
			}
		}
		break;
	}
}

static inline int simulated_ioctl(unsigned int opt, unsigned long args)
{
	if (opt == FAM_ATOMIC_32_FETCH_AND_ADD ||
	    opt == FAM_ATOMIC_32_SWAP ||
	    opt == FAM_ATOMIC_32_COMPARE_AND_STORE) {
		ioctl_4((struct fam_atomic_args_32 *)args, opt);
	} else if (opt == FAM_ATOMIC_64_FETCH_AND_ADD ||
		   opt == FAM_ATOMIC_64_SWAP ||
		   opt == FAM_ATOMIC_64_COMPARE_AND_STORE) {
		ioctl_8((struct fam_atomic_args_64 *)args, opt);
	} else if (opt == FAM_ATOMIC_128_SWAP ||
		   opt == FAM_ATOMIC_128_COMPARE_AND_STORE ||
		   opt == FAM_ATOMIC_128_READ) {
		ioctl_16((struct fam_atomic_args_128 *)args, opt);
	} else {
		printf("ERROR: ioctl() invalid 'opt' argument\n");
		exit(-1);
	}

	return 0;
}

/*
 * TODO: For now, we'll simulate the kernel ioctl interface in user
 *	 space, where the 'offset' field will be a VA to the atomics.
 *	 It is named __ioctl() instead of ioctl() to to avoid issues
 *	 with multiple declarations with this and the "real" ioctl().
 */
static inline void __ioctl(int fd, unsigned int opt, unsigned long args)
{
	if (ioctl(fd, opt, args)) {
		printf("ERROR: fam_atomic operation failed due to an invalid address.\n");
		printf("       Please verify LFS + librarian are running and that the\n");
		printf("       fam atomic address parameter is from a valid mmap() on\n");
		printf("       a LFS file\n\n");
		raise(SIGSEGV);
	}
}

/*
 * Mutex for internal use for the library to protect write access
 * to the RCU rbtree. We take this lock when inserting and removing
 * nodes from the tree when registering and unregistering regions.
 *
 * NOTE: The lock does not need be taken for read access of the RCU
 * rbtree since RCU allows lockless reads. Only writes require mutual
 * exclusion.
 */
struct rcu_write_mutex {
	/*
	 * 1 indicates the mutex is available.
	 * 0 indicates the mutex is acquired with no waiters.
	 * < 0 indicates the mutex is acquired with waiters.
	 */
	int futex;
} __attribute__((__aligned__(64)));

static inline int futex_wait(int *uaddr, int val)
{
	return syscall(SYS_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static inline int futex_wake(int *uaddr, int val)
{
	return syscall(SYS_futex, uaddr, FUTEX_WAKE, val, NULL, NULL, 0);
}

static void rcu_write_mutex_lock(struct rcu_write_mutex *mutex)
{
	/*
	 * Fastpath. Decrement the futex. If the futex was 1, then
	 * the lock was available, and we now own the lock.
	 */
	if (__atomic_fetch_sub(&mutex->futex, 1, __ATOMIC_ACQUIRE) == 1)
		return;

	/* Slowpath */
        for (;;) {
		int val = mutex->futex;

		/*
		 * Before this thread goes to sleep, we need to guarantee
		 * that the futex is a negative value to indicate that
		 * there are waiters so that the unlocker would call
		 * futex_wake() to wake up the next waiter in the queue.
		 */
                if (val >= 0) {
			val = -1;
                        if (__atomic_exchange_n(&mutex->futex, val, __ATOMIC_ACQUIRE) == 1)
				return;
                }

		/*
		 * Go to sleep until the next thread in the futex queue
		 * wakes up this thread when it call futex_wake().
		 */
                futex_wait(&mutex->futex, val);
        }
}

static void rcu_write_mutex_unlock(struct rcu_write_mutex *mutex)
{
	/*
	 * Fastpath: If the previous futex value was 0, then
	 * there were no waiters and we can return.
	 */
	if (__atomic_exchange_n(&mutex->futex, 1, __ATOMIC_RELEASE) == 0)
		return;

	/*
	 * Else there are waiters. Wake up next waiter in futex queue.
	 */
	futex_wake(&mutex->futex, 1);
}

/*
 * Each node in the rbtree represents a registered mmapped region.
 *
 * @region_start: Pointer to start of registered region
 * @region_length: Length of registered region.
 * @fd: File descriptor associated with the mmapped registered region.
 * @offset: Offset between start of file to region_start.
 * @use_zbridge_atomics: If true, use zbridge atomics,
 *			 else use simualted atomics.
 */
struct region {
	void *rbtree_key;
	void *region_start;
	size_t region_length;
	int dev_fd;
	int lfs_fd;
	off_t region_offset;
	bool use_zbridge_atomics;
} __attribute__((__aligned__(64)));

int rcu_rbtree_region_compare(void *ptr1, void *ptr2)
{
	struct region *region1 = (struct region *)ptr1;
	struct region *region2 = (struct region *)ptr2;

	/*
	 * NOTE: When searching for regions, we need to check if the
	 *       VA of the atomic is within a region. That logic does
	 *       not need to be taken into account here. The rcu-rbtree
	 *       insert function takes a "begin" and "end" value, and
	 *       the rbtree search function checks for if the key is
	 *       within the range between begin and end.
	 *
	 *       Thus, the only thing we need to compare in this
	 *       generic rbtree compare function are the "keys".
	 */
	if (region1->rbtree_key < region2->rbtree_key)
		return -1;
	else if (region1->rbtree_key > region2->rbtree_key)
		return 1;
	else
		return 0;
}

static DEFINE_RCU_RBTREE(rbtree, rcu_rbtree_region_compare, malloc, free, call_rcu);
static struct rcu_write_mutex rcu_rbtree_lock = { 1 };

/*
 * Given information about a registered region, insert a node in the
 * rbtree representing the registered region.
 */
int rcu_rbtree_region_insert(void *region_start, size_t region_length,
			     int dev_fd, int lfs_fd, off_t offset,
			     bool use_zbridge_atomics)
{
	struct region *begin, *end;

	begin = malloc(sizeof(struct region));
	if (!begin)
		return -1;

	end = malloc(sizeof(struct region));
	if (!end) {
		free(begin);
		return -1;
	}

	/*
	 * The rbtree insert function takes both a "begin" and an "end"
	 * node as parameters, and the default rbtree search function
	 * checks if a key is within the range between begin" and end.
	 * Thus, we need to create both a "begin" and "end" region to
	 * satisfy this interface. The "end" node will only contain the
	 * key value. The rest of the information about the registered
	 * region will only be stored in the "begin" node.
	 */
	begin->rbtree_key = region_start;
	end->rbtree_key = region_start + region_length;

	begin->rbtree_key = region_start;
	begin->region_start = region_start;
	begin->region_length = region_length;
	begin->dev_fd = dev_fd;
	begin->lfs_fd = lfs_fd;
	begin->region_offset = offset;
	begin->use_zbridge_atomics = use_zbridge_atomics;

	/*
	 * RCU allows lockless reads, but write access still requires
	 * locking. So we'll take a spinlock before inserting the nodes
	 * in the rbtree.
	 */
	rcu_write_mutex_lock(&rcu_rbtree_lock);
	rcu_read_lock();

	rcu_rbtree_insert(&rbtree, (void *)begin, (void *)end);

	rcu_read_unlock();
	rcu_write_mutex_unlock(&rcu_rbtree_lock);

	return 0;
}

int rcu_rbtree_region_remove(void *region_start, size_t region_length)
{
	int ret = -1;
	struct region key;
	struct rcu_rbtree_node *node;

	key.rbtree_key = region_start;

        /*
         * RCU allows lockless reads, but write access still requires
         * locking. So we'll take a spinlock before inserting the nodes
         * in the rbtree.
         */
        rcu_write_mutex_lock(&rcu_rbtree_lock);
        rcu_read_lock();

	node = rcu_rbtree_search(&rbtree, rbtree.root, &key);
	if (!rcu_rbtree_is_nil(&rbtree, node)) {
		ret = 0;
		rcu_rbtree_remove(&rbtree, node);
	}

	rcu_read_unlock();
	rcu_write_mutex_unlock(&rcu_rbtree_lock);
}

/*
 * Returns true if region found, else returns false.
 */
bool rcu_rbtree_region_search(void *address, int *dev_fd, int *lfs_fd,
			     int64_t *region_start, off_t *region_offset,
			     bool *use_zbridge_atomics)
{
	int found = false;
	struct region key;
	struct rcu_rbtree_node *node;

	key.rbtree_key = address;

	/*
	 * Reads only require a call to "rcu_read_lock" and don't require
	 * any additional locking. No blocking should occur here.
	 */
	rcu_read_lock();

	node = rcu_rbtree_search(&rbtree, rbtree.root, &key);
	if (!rcu_rbtree_is_nil(&rbtree, node)) {
		struct region *region = (struct region *)node->begin;

		found = true;
		*dev_fd = region->dev_fd;
		*lfs_fd = region->lfs_fd;
		*region_start = (int64_t)region->region_start;
		*region_offset = region->region_offset;
		*use_zbridge_atomics = region->use_zbridge_atomics;
	}

	rcu_read_unlock();

	return ret;
}

/*
 * Check if the file associated with 'fd' specified in the register
 * function starts with '/lfs/'.
 */
static inline bool check_lfs_file(int fd)
{
	char proc_path[64];
	char filepath[16];

	if (fd < 0)
		return false;

	/*
	 * Find path associated with fd. Return -1, if
	 * unable to find filename.
	 */
	sprintf(proc_path, "/proc/self/fd/%d", fd);
	if (readlink(proc_path, filepath, 16) == -1)
		return false;

	filepath[15] = '\0';

	/*
	 * Check if the filename begins with "/lfs".
	 */
	if (strncmp(filepath, "/lfs/", 5) == 0)
		return true;

	return false;
}

static inline bool lfs_running(void)
{
        char *librarian_fs_str = "LibrarianFS /lfs";
        FILE *in = fopen("/proc/self/mounts", "r");
        char buffer[128];
        bool found = false;

        while (fgets(buffer, sizeof(buffer), in) != NULL) {
                if (strncmp(buffer, librarian_fs_str, sizeof(librarian_fs_str)) == 0) {
                        found = true;
                        break;
                }
        }

	return found;
}

int fam_atomic_register_region(void *region_start, size_t region_length,
			       int fd, off_t offset)
{
	bool use_zbridge_atomics = false;
	int lfs_fd, dev_fd;

	lfs_fd = fd;

	/*
	 * zbridge support is only available on ARM64, so avoid the
	 * overhead of check if the zbridge atomics should be used
	 * on x86 systems which only use the simulated atomics.
	 */
#ifdef __aarch64__
	/*
	 * TODO: This is temporary code. On TMAS, the ioctls are
	 * implemented in a separate driver and not a part of LFS, so
	 * we'll open the device file for the driver and use that fd. If
	 * the driver is not installed and the fam_atomic device file is
	 * not found, then we'll just use the simulated atomics. This
	 * means that on TMAS with zbridge support, the user must make
	 * sure that the fam atomic driver has been installed in order
	 * for the library to use the zbridge atomics.
	 */
	dev_fd = open("/dev/fam_atomic", O_RDONLY);
	if (dev_fd == -1) {
		printf("ERROR: fam_atomic_register_region(): This system\n");
		printf("       does not have the fam atomic driver installed.\n");
		printf("       The zbridge atomics would not get used\n");
		raise(SIGSEGV);
	}

	/*
	 * If both the device file is present and we're registering
	 * an LFS file, then we will use zbridge atomics.
	 */
	if (check_lfs_file(lfs_fd)) {
		/*
		 * TODO: This checks for if LFS is running when the user tries to use
		 *       zbridge atomics. This is a temporary check in order to
		 *       avoid a potential kernel panic. We can remove this when
		 *       the tm-fuse lfs_obtain_lza_and_book_offset() function contains
		 *       the check for if the file is really an LFS file.
		 */
		if (!lfs_running()) {
			printf("ERROR: fam_atomic_register_region(): LFS is not running\n");
			printf("       on this node. It must be running in order to use\n");
			printf("       atomics on FAM\n");
			raise(SIGSEGV);
		}

		use_zbridge_atomics = true;
	}
#endif

	rcu_rbtree_region_insert(region_start, region_length, dev_fd, lfs_fd,
				 offset, use_zbridge_atomics);
}

void fam_atomic_unregister_region(void *region_start, size_t region_length)
{
	rcu_rbtree_region_remove(region_start, region_length);
}

/*
 * Returns true if we should use zbridge atomics, else returns false.
 */
static bool fam_atomic_get_fd_offset(void *address, int *dev_fd, int *lfs_fd, int64_t *offset)
{
	struct node *curr = NULL;
	bool ret = false;
	bool region_exists;
	bool use_zbridge_atomics;
	int64_t region_start;

	region_exists = rcu_rbtree_region_search(address, dev_fd, lfs_fd, &region_start, offset, &use_zbridge_atomics);

	if (!region_exists) {
		/*
		 * Generate a segmentation fault.
		 */
		printf("ERROR: fam atomic variable used without being registered. Mapped regions containing\n");
		printf("       fam atomics must be registered with fam_atomic_register_region() before\n");
		printf("       the fam atomics within the region can be used.\n");
		raise(SIGSEGV);
	}

	if (use_zbridge_atomics)
		ret = true;

	/*
	 * TODO: For now, we'll use the VA as the LFS file offset. On TMAS,
	 * the ioctl for the atomics is in a separate driver, not part of
	 * LFS, and requires the atomic VA. The simulated atomics also operate
	 * directly on the VA.
	 */
	if (use_zbridge_atomics)
		*offset = (int64_t)address - region_start + *offset;
	else
		*offset = (int64_t)address;

	return ret;
}

int32_t fam_atomic_32_fetch_add(int32_t *address, int32_t increment)
{
	int32_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_32 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p32_0 = increment;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_32_FETCH_AND_ADD, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_32_FETCH_AND_ADD, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_fetch_add(int64_t *address, int64_t increment)
{
	int64_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_64 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p64_0 = increment;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_64_FETCH_AND_ADD, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_64_FETCH_AND_ADD, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

int32_t fam_atomic_32_swap(int32_t *address, int32_t value)
{
	int32_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_32 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p32_0 = value;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_32_SWAP, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_32_SWAP, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_swap(int64_t *address, int64_t value)
{
	int64_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_64 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p64_0 = value;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_64_SWAP, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_64_SWAP, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

void fam_atomic_128_swap(int64_t *address, int64_t value[2], int64_t result[2])
{
	int64_t old[2];
	int dev_fd, lfs_fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p128_0[0] = value[0];
	args.p128_0[1] = value[1];

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_128_SWAP, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_128_SWAP, (unsigned long)&args);

	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

int32_t fam_atomic_32_compare_store(int32_t *address,
						 int32_t compare,
						 int32_t store)
{
	int32_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_32 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p32_0 = compare;
	args.p32_1 = store;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_32_COMPARE_AND_STORE, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_32_COMPARE_AND_STORE, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_compare_store(int64_t *address,
					  	 int64_t compare,
						 int64_t store)
{
	int64_t prev;
	int dev_fd, lfs_fd;
	int64_t offset;
	struct fam_atomic_args_64 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p64_0 = compare;
	args.p64_1 = store;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_64_COMPARE_AND_STORE, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_64_COMPARE_AND_STORE, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

void fam_atomic_128_compare_store(int64_t *address,
					       int64_t compare[2],
					       int64_t store[2],
					       int64_t result[2])
{
	int64_t old[2];
	int dev_fd, lfs_fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;
	args.p128_0[0] = compare[0];
	args.p128_0[1] = compare[1];
	args.p128_1[0] = store[0];
	args.p128_1[1] = store[1];

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_128_COMPARE_AND_STORE, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_128_COMPARE_AND_STORE, (unsigned long)&args);

	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

int32_t fam_atomic_32_read(int32_t *address)
{
	return fam_atomic_32_fetch_add(address, 0);
}

int64_t fam_atomic_64_read(int64_t *address)
{
	return fam_atomic_64_fetch_add(address, 0);
}

extern void fam_atomic_128_read(int64_t *address, int64_t result[2])
{
	int64_t old[2];
	int dev_fd, lfs_fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;
	bool use_zbridge_atomics;

	use_zbridge_atomics = fam_atomic_get_fd_offset(address, &dev_fd, &lfs_fd, &offset);

	args.lfs_fd = lfs_fd;
	args.offset = offset;

	if (use_zbridge_atomics)
		__ioctl(dev_fd, FAM_ATOMIC_128_READ, (unsigned long)&args);
	else
		simulated_ioctl(FAM_ATOMIC_128_READ, (unsigned long)&args);


	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

void fam_atomic_32_write(int32_t *address, int32_t value)
{
	/* This is a write operation, so no need to return prev value. */
	(void) fam_atomic_32_swap(address, value);
}

void fam_atomic_64_write(int64_t *address, int64_t value)
{
	/* This is a write operation, so no need to return prev value. */
	(void) fam_atomic_64_swap(address, value);
}

void fam_atomic_128_write(int64_t *address, int64_t value[2])
{
	/*
	 * Only a write operation, so we won't need to use the 'result',
	 * but we need to create this in order to use the 128 swap API.
	 */
	int64_t result[2];

	fam_atomic_128_swap(address, value, result);
}

/*
 * TODO: For fetch_{and,or,xor}, we always guess the initial CAS 'compare'
 * value as 0. As an optimization, we can consider more advanced techniques
 * such as maintaining a cache of values stored to recently used atomics.
 * This can improve the accuracy of the guess.
 */
int32_t fam_atomic_32_fetch_and(int32_t *address, int32_t arg)
{
	/*
	 * Reading the fam atomic value requires an additional system call.
	 * So we'll just guess the value as 0 for the initial CAS. If the
	 * guess is incorrect, we'll treat the CAS() as the atomic read
	 * since CAS() returns the prev value.
	 */
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_store(address, prev, prev & arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_and(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_store(address, prev, prev & arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int32_t fam_atomic_32_fetch_or(int32_t *address, int32_t arg)
{
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_store(address, prev, prev | arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_or(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_store(address, prev, prev | arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int32_t fam_atomic_32_fetch_xor(int32_t *address, int32_t arg)
{
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_store(address, prev, prev ^ arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_xor(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_store(address, prev, prev ^ arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

void fam_spin_lock_init(struct fam_spinlock *lock)
{
        fam_atomic_64_write(&lock->head_tail, 0);
}

void fam_spin_lock(struct fam_spinlock *lock)
{
        struct fam_spinlock inc = {
                .tickets = {
                        .head = 0,
                        .tail = 1
                }
        };

        /* Fetch the current values and bump the tail by one */
        inc.head_tail = fam_atomic_64_fetch_add(&lock->head_tail, inc.head_tail);

        if (inc.tickets.head != inc.tickets.tail) {
                for (;;) {
                        inc.tickets.head = fam_atomic_32_fetch_add(&lock->tickets.head, 0);
                        if (inc.tickets.head == inc.tickets.tail)
                                break;
                }
        }
        __sync_synchronize();
}

bool fam_spin_trylock(struct fam_spinlock *lock)
{
        struct fam_spinlock old, new;
        bool ret;

        old.head_tail = fam_atomic_64_fetch_add(&lock->head_tail, (int64_t) 0);
        if (old.tickets.head != old.tickets.tail)
                return 0;

        new.tickets.head = old.tickets.head;
        new.tickets.tail = old.tickets.tail + 1;
        ret = fam_atomic_64_compare_store(&lock->head_tail, old.head_tail, new.head_tail) == old.head_tail;
        __sync_synchronize();
        return ret;
}

void fam_spin_unlock(struct fam_spinlock *lock)
{
        (void) fam_atomic_32_fetch_add(&lock->tickets.head, 1);
        __sync_synchronize();
}
