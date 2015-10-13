/*
 * Copyright © 2015 Jason Low <jason.low2@hpe.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include "fam_atomic.h"

#define LOCK_PREFIX_HERE                  \
	".pushsection .smp_locks,\"a\"\n" \
	".balign 4\n"                     \
	".long 671f - .\n"                \
	".popsection\n"                   \
	"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#define u32 unsigned int
#define u64 unsigned long long

void fam_atomic_compare_exchange_wrong_size(void);
void fam_atomic_xadd_wrong_size(void);
void fam_atomic_xchg_wrong_size(void);

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

#define x86_cmpxchg(ptr, old, new)	__x86_cmpxchg(ptr, old, new, sizeof(*(ptr)))
#define x86_xchg(ptr, v)		__x86_xchg_op((ptr), (v), xchg, "")
#define x86_xadd(ptr, inc)		__x86_xadd((ptr), (inc), LOCK_PREFIX)

#define __cmpxchg16(pfx, p1, p2, o1, o2, n1, n2)			\
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

#define cmpxchg16(p1, p2, o1, o2, n1, n2) \
	__cmpxchg16(LOCK_PREFIX, p1, p2, o1, o2, n1, n2)

static inline void ioctl_4(struct fam_atomic_args_32 *args, unsigned int opt)
{
	int32_t *atomic = (int32_t *)args->offset;
	int32_t *result_ptr = &args->p32_0;
	int32_t prev;

	switch (opt) {
	case FAM_ATOMIC_32_FETCH_AND_ADD:
		prev = x86_xadd(atomic, args->p32_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_32_SWAP:
		prev = x86_xchg(atomic, args->p32_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_32_COMPARE_AND_STORE:
		prev = x86_cmpxchg(atomic, args->p32_0, args->p32_1);
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
		prev = x86_xadd(atomic, args->p64_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_64_SWAP:
		prev = x86_xchg(atomic, args->p64_0);
		*result_ptr = prev;
		break;

	case FAM_ATOMIC_64_COMPARE_AND_STORE:
		prev = x86_cmpxchg(atomic, args->p64_0, args->p64_1);
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
			old[0] = x86_xadd(address1, 0);
			old[1] = x86_xadd(address2, 0);

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
				old[0] = x86_xadd(address1, 0);
				old[1] = x86_xadd(address2, 0);

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
			old[0] = x86_xadd(address1, 0);
			old[1] = x86_xadd(address2, 0);

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

/*
 * TODO: For now, we'll simulate the kernel ioctl interface in user
 *	 space, where the 'offset' field will be a VA to the atomics.
 *	 It is named __ioctl() instead of ioctl() to to avoid issues
 *	 with multiple declarations with this and the "real" ioctl().
 */
static inline int __ioctl(int fd, unsigned int opt, unsigned long args)
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
}

/* Each node represents a registered NVM atomic region. */
struct node {
	void *region_start;
	size_t region_length;
	int fd;
	off_t region_offset;
	/* Next node in the linked list. */
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
 * TODO: Convert this to a balanced binary search tree for O(log(n)) search.
 *
 * Per-thread list of registered NVM atomic regions. This stores
 * the information of the mapping from atomic VA to (fd, region_offset)
 * pair, which get's passed to the kernel.
 */
static __thread struct list fam_atomic_region_list = { .head = NULL };

int fam_atomic_register_region(void *region_start, size_t region_length, int fd, off_t offset)
{
	struct node *new_node = malloc(sizeof(struct node));

	if (!new_node)
		return -1;

	new_node->region_start = region_start;
	new_node->region_length = region_length;
	new_node->fd = fd;
	new_node->region_offset = offset;

	/* TODO: Detect overlapping regions? */
	list_add(&fam_atomic_region_list, new_node);

	return 0;
}

void fam_atomic_unregister_region(void *region_start, size_t region_length)
{
	struct node *curr, *prev;

	prev = NULL;

	for (curr = fam_atomic_region_list.head; curr != NULL; curr = curr->next) {
		if (curr->region_start == region_start &&
		    curr->region_length == region_length)
			break;

		prev = curr;
	}

	/* Error, no such region. */
	if (!curr)
		return;

	list_del(&fam_atomic_region_list, prev, curr);
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

	for (curr = fam_atomic_region_list.head; curr != NULL; curr = curr->next) {
		if (curr->region_start <= address &&
		    curr->region_start + curr->region_length >= address)
			break;
	}

	/*
	 * No region containing the atomic has been registered.
	 */
	if (!curr) {
		/*
		 * Generate a segmentation fault.
		 */
		printf("ERROR: fam atomic variable used without being registered. NVM regions containing\n");
		printf("       fam atomics must be registered with fam_atomic_register_region() before\n");
		printf("       the fam atomics within the region can be used\n");
		kill(0, SIGSEGV);
	}

	*fd = curr->fd;
	*offset = (int64_t)address - (int64_t)curr->region_start +
		  (int64_t)curr->region_offset;
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
