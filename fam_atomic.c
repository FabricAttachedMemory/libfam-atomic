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
#include "fam_atomic.h"

#define LOCK_PREFIX_HERE                  \
	".pushsection .smp_locks,\"a\"\n" \
	".balign 4\n"                     \
	".long 671f - .\n"                \
	".popsection\n"                   \
	"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define u32 unsigned int
#define u64 unsigned long long

void fam_atomic_compare_exchange_wrong_size(void);
void fam_atomic_xadd_wrong_size(void);
void fam_atomic_xchg_wrong_size(void);
void fam_atomic_arch_not_supported(void);

#ifdef __x86_64__

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
static inline int __ioctl(int fd, unsigned int opt, unsigned long args)
{
#ifdef TMAS
	/*
	 * On TMAS, we'll make the "real" ioctl() system call.
	 */
	return ioctl(fd, opt, args);
#else
	return simulated_ioctl(opt, args);
#endif
}

/*
 * A simple read/write lock for internal use within library.
 * The read lock will be taken significantly more often than
 * the write lock, so we must ensure there is no writer starvation.
 * Writers get priority for getting the lock. We don't need to
 * worry about reader starvation in this library because we only
 * need to take the write lock when registering and unregistering
 * atomics, which are less common operations.
 */
struct rw_lock {
	/*
	 * 0x1000000: free
	 * 0: writer
	 * positive value less than 0x100000: reader(s)
	 */
	int value;
	int nr_write_waiters;
} __attribute__((__aligned__(64)));

#define UNLOCKED   0x1000000
#define WRITE_BIAS 0x1000000
#define READ_BIAS  0x1

static inline void read_lock(struct rw_lock *lock)
{
	/* Fastpath */
	if (xadd(&lock->value, -READ_BIAS) > 0 &&
	    lock->nr_write_waiters == 0)
		return;

	/* Slowpath - contending for lock */
	xadd(&lock->value, READ_BIAS);

	for (;;) {
		int value;

		while (lock->nr_write_waiters > 0);

		value = lock->value;
		if (value > 0 &&
		    cmpxchg(&lock->value, value, value - READ_BIAS) == value)
			return;
	}
}

static inline void read_unlock(struct rw_lock *lock)
{
	xadd(&lock->value, READ_BIAS);
}

static inline void write_lock(struct rw_lock *lock)
{
	/* Fastpath */
	if (xadd(&lock->value, -WRITE_BIAS) == UNLOCKED)
		return;

	/* Slowpath - contending for lock */
	xadd(&lock->value, WRITE_BIAS);
	xadd(&lock->nr_write_waiters, 1);
	for (;;) {
		if (lock->value == UNLOCKED &&
		    cmpxchg(&lock->value, UNLOCKED, 0) == UNLOCKED)
			break;
	}
	xadd(&lock->nr_write_waiters, -1);
}

static inline void write_unlock(struct rw_lock *lock)
{
	xadd(&lock->value, WRITE_BIAS);
}

/*
 * Each node represents a registered mmapped region.
 *
 * @region_start: Pointer to start of registered region
 * @region_length: Length of registered region.
 * @fd: File descriptor associated with the mmapped registered region.
 * @offset: Offset between start of file to region_start.
 * @use_zbridge_atomics: If true, use zbridge atomics,
 *			 else use simualted atomics.
 */
struct node {
	void *region_start;
	size_t region_length;
	int fd;
	off_t region_offset;
	bool use_zbridge_atomics;
	struct node *next;
};

struct list {
	struct node *head;
};

static void list_add(struct list *list, struct node *node)
{
	node->next = list->head;
	list->head = node;
}

static void list_del(struct list *list, struct node *prev, struct node *node)
{
	if (!prev) {
		assert(list->head == node);
		list->head = node->next;
	} else {
		prev->next = node->next;
	}

	free(node);
}

/*
 * TODO: Convert this to a red-black binary search tree for O(log(n)) search.
 *
 * List of registered FAM atomic regions. This stores the information of the
 * mapping from atomic VA to (fd, region_offset) pair, which gets passed in
 * the ioctl() call to the kernel.
 */
static struct list fam_atomic_region_list = { NULL };
static struct rw_lock fam_atomic_list_lock = { UNLOCKED, 0 };

int fam_atomic_register_region(void *region_start, size_t region_length,
			       int fd, off_t offset)
{
	struct node *new_node = malloc(sizeof(struct node));

	if (!new_node)
		return -1;

	new_node->region_start = region_start;
	new_node->region_length = region_length;
	new_node->fd = fd;
	new_node->region_offset = offset;
	new_node->use_zbridge_atomics = false;

#ifdef TMAS
	/*
	 * On TMAS, the ioctls are implemented in a separate driver
	 * and not a part of LFS, so we'll open the device file for
	 * the driver and use that fd.
	 */
	new_node->fd = open("/dev/fam_atomic", O_RDWR);
	if (new_node->fd == -1) {
		printf("fam_atomic_register_region(): Unable to open device\n");
		printf("file. Please verify that the fam_atomic TMAS driver\n");
		printf("has been installed on the system.\n");
		return -1;
	}

	/* TODO: Currently, the offset is just the VA. */
	if (check_zbridge_atomics(new_node->fd, (int64_t)region_start)
		new_node->use_zbridge_atomics = true;
#endif

	/* TODO: Detect overlapping regions? */
	write_lock(&fam_atomic_list_lock);
	list_add(&fam_atomic_region_list, new_node);
	write_unlock(&fam_atomic_list_lock);

	return 0;
}

void fam_atomic_unregister_region(void *region_start, size_t region_length)
{
	struct node *curr, *prev;

	prev = NULL;

	write_lock(&fam_atomic_list_lock);

	for (curr = fam_atomic_region_list.head; curr != NULL; curr = curr->next) {
		if (curr->region_start == region_start &&
		    curr->region_length == region_length)
			break;

		prev = curr;
	}

	/* Error, no such region. */
	if (!curr) {
		write_unlock(&fam_atomic_list_lock);
		return;
	}

#ifdef TMAS
	close(curr->fd);
#endif

	list_del(&fam_atomic_region_list, prev, curr);

	write_unlock(&fam_atomic_list_lock);
}

/*
 * Check if it is possible to invoke a zbridge atomic read on
 * the first 4 bytes specified by the (fd, offset) pair.
 */
static inline bool check_zbridge_atomics(int fd, int64_t offset)
{
	struct fam_atomic_args_32 args;

	args.offset = offset;
	args.p32_0 = 0;
	args.p32_1 = 0;

	if (__ioctl(fd, FAM_ATOMIC_32_FETCH_AND_ADD, (unsigned long)&args))
		return false;

	return true;
}

/*
 * Given an address to an fam-atomic, find the associated fd and offset.
 * This is done by searching the list: fam_atomic_region_list. The NVM region
 * containing the fam-atomic must have been registered in order for this
 * function to succeed. If the region containing the atomic has not been
 * registered, then this function will generate a segmentation fault.
 */
static void fam_atomic_get_fd_offset(void *address, int *fd, int64_t *offset)
{
	struct node *curr = NULL;

	read_lock(&fam_atomic_list_lock);

	for (curr = fam_atomic_region_list.head; curr != NULL; curr = curr->next) {
		if (curr->region_start <= address &&
		    curr->region_start + curr->region_length >= address)
			break;
	}

	/*
	 * No region containing the atomic has been registered.
	 */
	if (!curr) {
		read_unlock(&fam_atomic_list_lock);
		/*
		 * Generate a segmentation fault.
		 */
		printf("ERROR: fam atomic variable used without being registered. NVM regions containing\n");
		printf("       fam atomics must be registered with fam_atomic_register_region() before\n");
		printf("       the fam atomics within the region can be used\n");
		raise(SIGSEGV);
	}

	*fd = curr->fd;
	*offset = (int64_t)address - (int64_t)curr->region_start +
		  (int64_t)curr->region_offset;

	read_unlock(&fam_atomic_list_lock);

#ifdef TMAS
	/*
	 * We'll directly pass the VA to the ioctl rather than the
	 * LFS file offset, since the ioctls for the atomics will be
	 * in a separate driver and not part of LFS.
	 */
	*offset = (int64_t)address;
#endif
}

int32_t fam_atomic_32_fetch_and_add_unpadded(int32_t *address, int32_t increment)
{
	int32_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_32 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p32_0 = increment;

	__ioctl(fd, FAM_ATOMIC_32_FETCH_AND_ADD, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_fetch_and_add_unpadded(int64_t *address, int64_t increment)
{
	int64_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_64 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p64_0 = increment;

	__ioctl(fd, FAM_ATOMIC_64_FETCH_AND_ADD, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

int32_t fam_atomic_32_swap_unpadded(int32_t *address, int32_t value)
{
	int32_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_32 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p32_0 = value;

	__ioctl(fd, FAM_ATOMIC_32_SWAP, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_swap_unpadded(int64_t *address, int64_t value)
{
	int64_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_64 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p64_0 = value;

	__ioctl(fd, FAM_ATOMIC_64_SWAP, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

void fam_atomic_128_swap_unpadded(int64_t *address, int64_t value[2], int64_t result[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p128_0[0] = value[0];
	args.p128_0[1] = value[1];

	__ioctl(fd, FAM_ATOMIC_128_SWAP, (unsigned long)&args);

	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

int32_t fam_atomic_32_compare_and_store_unpadded(int32_t *address,
						 int32_t compare,
						 int32_t store)
{
	int32_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_32 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p32_0 = compare;
	args.p32_1 = store;

	__ioctl(fd, FAM_ATOMIC_32_COMPARE_AND_STORE, (unsigned long)&args);

	prev = args.p32_0;

	return prev;
}

int64_t fam_atomic_64_compare_and_store_unpadded(int64_t *address,
					  	 int64_t compare,
						 int64_t store)
{
	int64_t prev;
	int fd;
	int64_t offset;
	struct fam_atomic_args_64 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p64_0 = compare;
	args.p64_1 = store;

	__ioctl(fd, FAM_ATOMIC_64_COMPARE_AND_STORE, (unsigned long)&args);

	prev = args.p64_0;

	return prev;
}

void fam_atomic_128_compare_and_store_unpadded(int64_t *address,
					       int64_t compare[2],
					       int64_t store[2],
					       int64_t result[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	args.p128_0[0] = compare[0];
	args.p128_0[1] = compare[1];
	args.p128_1[0] = store[0];
	args.p128_1[1] = store[1];

	__ioctl(fd, FAM_ATOMIC_128_COMPARE_AND_STORE, (unsigned long)&args);

	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

int32_t fam_atomic_32_read_unpadded(int32_t *address)
{
	return fam_atomic_32_fetch_and_add_unpadded(address, 0);
}

int64_t fam_atomic_64_read_unpadded(int64_t *address)
{
	return fam_atomic_64_fetch_and_add_unpadded(address, 0);
}

extern void fam_atomic_128_read_unpadded(int64_t *address, int64_t result[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	struct fam_atomic_args_128 args;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	args.offset = (int64_t)address;
	__ioctl(fd, FAM_ATOMIC_128_READ, (unsigned long)&args);

	result[0] = args.p128_0[0];
	result[1] = args.p128_0[1];
}

void fam_atomic_32_write_unpadded(int32_t *address, int32_t value)
{
	/* This is a write operation, so no need to return prev value. */
	(void) fam_atomic_32_swap_unpadded(address, value);
}

void fam_atomic_64_write_unpadded(int64_t *address, int64_t value)
{
	/* This is a write operation, so no need to return prev value. */
	(void) fam_atomic_64_swap_unpadded(address, value);
}

void fam_atomic_128_write_unpadded(int64_t *address, int64_t value[2])
{
	/*
	 * Only a write operation, so we won't need to use the 'result',
	 * but we need to create this in order to use the 128 swap API.
	 */
	int64_t result[2];

	fam_atomic_128_swap_unpadded(address, value, result);
}

/*
 * TODO: For fetch_{and,or,xor}, we always guess the initial CAS 'compare'
 * value as 0. As an optimization, we can consider more advanced techniques
 * such as maintaining a cache of values stored to recently used atomics.
 * This can improve the accuracy of the guess.
 */
int32_t fam_atomic_32_fetch_and_unpadded(int32_t *address, int32_t arg)
{
	/*
	 * Reading the fam atomic value requires an additional system call.
	 * So we'll just guess the value as 0 for the initial CAS. If the
	 * guess is incorrect, we'll treat the CAS() as the atomic read
	 * since CAS() returns the prev value.
	 */
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_and_store_unpadded(address, prev, prev & arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_and_unpadded(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_and_store_unpadded(address, prev, prev & arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int32_t fam_atomic_32_fetch_or_unpadded(int32_t *address, int32_t arg)
{
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_and_store_unpadded(address, prev, prev | arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_or_unpadded(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_and_store_unpadded(address, prev, prev | arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int32_t fam_atomic_32_fetch_xor_unpadded(int32_t *address, int32_t arg)
{
	int32_t prev = 0;

	for (;;) {
		int32_t actual = fam_atomic_32_compare_and_store_unpadded(address, prev, prev ^ arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

int64_t fam_atomic_64_fetch_xor_unpadded(int64_t *address, int64_t arg)
{
	int64_t prev = 0;

	for (;;) {
		int64_t actual = fam_atomic_64_compare_and_store_unpadded(address, prev, prev ^ arg);

		if (actual == prev)
			return prev;

		prev = actual;
	}
}

void fam_spin_lock_unpadded(struct fam_spinlock_unpadded *lock)
{
        struct fam_spinlock_unpadded inc = {
                .tickets = {
                        .head = 0,
                        .tail = 1
                }
        };

        /* Fetch the current values and bump the tail by one */
        inc.head_tail = fam_atomic_64_fetch_and_add_unpadded(&lock->head_tail, inc.head_tail);

        if (inc.tickets.head != inc.tickets.tail) {
                for (;;) {
                        inc.tickets.head = fam_atomic_32_fetch_and_add_unpadded(&lock->tickets.head, 0);
                        if (inc.tickets.head == inc.tickets.tail)
                                break;
                }
        }
        __sync_synchronize();
}

bool fam_spin_trylock_unpadded(struct fam_spinlock_unpadded *lock)
{
        struct fam_spinlock_unpadded old, new;
        bool ret;

        old.head_tail = fam_atomic_64_fetch_and_add_unpadded(&lock->head_tail, (int64_t) 0);
        if (old.tickets.head != old.tickets.tail)
                return 0;

        new.tickets.head = old.tickets.head;
        new.tickets.tail = old.tickets.tail + 1;
        ret = fam_atomic_64_compare_and_store_unpadded(&lock->head_tail, old.head_tail, new.head_tail) == old.head_tail;
        __sync_synchronize();
        return ret;
}

void fam_spin_unlock_unpadded(struct fam_spinlock_unpadded *lock)
{
        (void) fam_atomic_32_fetch_and_add_unpadded(&lock->tickets.head, 1);
        __sync_synchronize();
}
