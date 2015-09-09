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

#define __x86_xchg_op(ptr, arg, op, lock)                               \
        ({                                                              \
                __typeof__ (*(ptr)) __ret = (arg);                      \
                switch (sizeof(*(ptr))) {                               \
                case 4:                                                 \
                        asm volatile (lock #op "l %0, %1\n"             \
                                      : "+r" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                case 8:                                                 \
                        asm volatile (lock #op "q %q0, %1\n"            \
                                      : "+r" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                default:                                                \
                       fam_atomic_ ## op ## _wrong_size();              \
                }                                                       \
                __ret;                                                  \
        })

#define __x86_xadd(ptr, inc, lock)	__x86_xchg_op((ptr), (inc), xadd, lock)

#define x86_cmpxchg(ptr, old, new)	__x86_cmpxchg(ptr, old, new, sizeof(*(ptr)))
#define x86_xchg(ptr, v)		__x86_xchg_op((ptr), (v), xchg, "")
#define x86_xadd(ptr, inc)		__x86_xadd((ptr), (inc), LOCK_PREFIX)

#define __cmpxchg16(pfx, p1, p2, o1, o2, n1, n2)                        \
({                                                                      \
        bool __ret;                                                     \
        __typeof__(*(p1)) __old1 = (o1), __new1 = (n1);                 \
        __typeof__(*(p2)) __old2 = (o2), __new2 = (n2);                 \
        asm volatile(pfx "cmpxchg%c4b %2; sete %0"                      \
                     : "=a" (__ret), "+d" (__old2),                     \
                       "+m" (*(p1)), "+m" (*(p2))                       \
                     : "i" (2 * sizeof(long)), "a" (__old1),            \
                       "b" (__new1), "c" (__new2));                     \
        __ret;                                                          \
})

#define cmpxchg16(p1, p2, o1, o2, n1, n2) \
        __cmpxchg16(LOCK_PREFIX, p1, p2, o1, o2, n1, n2)

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
 * This is done by searching the list: fam_atomic_region_list.
 * The NVM region containing the fam-atomic must have been registered in
 * order for this function to succeed.
 *
 * If the region containing the atomic has not been registered, then this
 * function will generate a segmentation fault.
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
		printf("Error: NVM region not registered as fam-atomic region?\n");
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

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_xadd(address, increment);

	return prev;
}

int64_t fam_atomic_64_fetch_and_add_unpadded(int64_t *address, int64_t increment)
{
	int64_t prev;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_xadd(address, increment);

	return prev;
}

int32_t fam_atomic_32_swap_unpadded(int32_t *address, int32_t value)
{
	int32_t prev;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_xchg(address, value);

	return prev;
}

int64_t fam_atomic_64_swap_unpadded(int64_t *address, int64_t value)
{
	int64_t prev;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_xchg(address, value);

	return prev;
}

void fam_atomic_128_swap_unpadded(int64_t *address, int64_t value[2], int64_t result[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	int64_t *address2 = (int64_t *)((int64_t)address + sizeof(int64_t));

	fam_atomic_get_fd_offset(address, &fd, &offset);

	for (;;) {
		old[0] = fam_atomic_64_read_unpadded(address);
		old[1] = fam_atomic_64_read_unpadded(address2);
		ret = cmpxchg16(address, address2, old[0], old[1], value[0], value[1]);

		if (ret) {
			result[0] = old[0];
			result[1] = old[1];
			return;
		}
	}
}

int32_t fam_atomic_32_compare_and_store_unpadded(int32_t *address,
						 int32_t compare,
						 int32_t store)
{
	int32_t prev;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_cmpxchg(address, compare, store);

	return prev;
}

int64_t fam_atomic_64_compare_and_store_unpadded(int64_t *address,
					  	 int64_t compare,
						 int64_t store)
{
	int64_t prev;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	prev = x86_cmpxchg(address, compare, store);

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
	int64_t *address2 = (int64_t *)((int64_t)address + sizeof(int64_t));

	fam_atomic_get_fd_offset(address, &fd, &offset);

	for (;;) {
		old[0] = fam_atomic_64_read_unpadded(address);
		old[1] = fam_atomic_64_read_unpadded(address + sizeof(int64_t));
		ret = cmpxchg16(address, address2, compare[0], compare[1],
						   store[0], store[1]);

		if (ret) {
			/*
			 * Success, the previous values match the compare values.
			 */
			result[0] = compare[0];
			result[1] = compare[1];
			return;
		} else {
			/*
			 * cmpxchg16 returned false. Make sure the sampled
			 * "old" values do not match the compare values so that
			 * users can correctly check that the operation did not
			 * succeed. Otherwise, we will retry the operation.
			 */
			if (old[0] != compare[0] || old[1] != compare[1]) {
				result[0] = old[0];
				result[1] = old[1];
				return;
			}
		}
	}
}

int32_t fam_atomic_32_read_unpadded(int32_t *address)
{
	int32_t value;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);

	value =  x86_xadd(address, 0);

	return value;
}

int64_t fam_atomic_64_read_unpadded(int64_t *address)
{
	int64_t value;
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	
	value = x86_xadd(address, 0);

	return value;
}

extern void fam_atomic_128_read_unpadded(int64_t *address, int64_t result[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	int64_t *address2 = (int64_t *)((int64_t)address + sizeof(int64_t));

	fam_atomic_get_fd_offset(address, &fd, &offset);

	for (;;) {
		old[0] = fam_atomic_64_read_unpadded(address);
		old[1] = fam_atomic_64_read_unpadded(address2);
		ret = cmpxchg16(address, address2, old[0], old[1], old[0], old[1]);

		if (ret) {
			result[0] = old[0];
			result[1] = old[1];
			return;
		}
	}
}

void fam_atomic_32_write_unpadded(int32_t *address, int32_t value)
{
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	/* Only a write operation, no need to return prev value. */
	x86_xchg(address, value);
}

void fam_atomic_64_write_unpadded(int64_t *address, int64_t value)
{
	int fd;
	int64_t offset;

	fam_atomic_get_fd_offset(address, &fd, &offset);
	/* Only a write operation, no need to return prev value. */
	x86_xchg(address, value);
}

void fam_atomic_128_write_unpadded(int64_t *address, int64_t value[2])
{
	int64_t old[2];
	int fd;
	int64_t offset;
	bool ret;
	int64_t *address2 = (int64_t *)((int64_t)address + sizeof(int64_t));

	fam_atomic_get_fd_offset(address, &fd, &offset);

	for (;;) {
		old[0] = fam_atomic_64_read_unpadded(address);
		old[1] = fam_atomic_64_read_unpadded(address2);
		ret = cmpxchg16(address, address2, old[0], old[1], value[0], value[1]);
		if (ret)
			return;
	}
}

int32_t fam_atomic_32_fetch_and_add(struct fam_atomic_32 *address, int32_t increment)
{
	return fam_atomic_32_fetch_and_add_unpadded(&address->__v__, increment);
}

int64_t fam_atomic_64_fetch_and_add(struct fam_atomic_64 *address, int64_t increment)
{
	return fam_atomic_64_fetch_and_add_unpadded(&address->__v__, increment);
}

int32_t fam_atomic_32_swap(struct fam_atomic_32 *address, int32_t value)
{
	return fam_atomic_32_swap_unpadded(&address->__v__, value);
}

int64_t fam_atomic_64_swap(struct fam_atomic_64 *address, int64_t value)
{
	return fam_atomic_64_swap_unpadded(&address->__v__, value);
}

void fam_atomic_128_swap(struct fam_atomic_128 *address, int64_t value[2], int64_t result[2])
{
	fam_atomic_128_swap_unpadded(address->__v__, value, result);
}

int32_t fam_atomic_32_compare_and_store(struct fam_atomic_32 *address,
					int32_t compare,
					int32_t store)
{
	return fam_atomic_32_compare_and_store_unpadded(&address->__v__, compare, store);
}

int64_t fam_atomic_64_compare_and_store(struct fam_atomic_64 *address,
					int64_t compare,
					int64_t store)
{
	return fam_atomic_64_compare_and_store_unpadded(&address->__v__, compare, store);
}

void fam_atomic_128_compare_and_store(struct fam_atomic_128 *address,
				      int64_t compare[2],
				      int64_t store[2],
				      int64_t result[2])
{
	return fam_atomic_128_compare_and_store_unpadded(address->__v__, compare, store, result);
}

int32_t fam_atomic_32_read(struct fam_atomic_32 *address)
{
	return fam_atomic_32_read_unpadded(&address->__v__);
}

int64_t fam_atomic_64_read(struct fam_atomic_64 *address)
{
	return fam_atomic_64_read_unpadded(&address->__v__);
}

void fam_atomic_128_read(struct fam_atomic_128 *address, int64_t result[2])
{
	fam_atomic_128_read_unpadded(address->__v__, result);
}

void fam_atomic_32_write(struct fam_atomic_32 *address, int32_t value)
{
	fam_atomic_32_write_unpadded(&address->__v__, value);
}

void fam_atomic_64_write(struct fam_atomic_64 *address, int64_t value)
{
	fam_atomic_64_write_unpadded(&address->__v__, value);
}

void fam_atomic_128_write(struct fam_atomic_128 *address, int64_t value[2])
{
	fam_atomic_128_write_unpadded(address->__v__, value);
}

/*
 * Spinlocks
 */
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

void fam_spin_lock(struct fam_spinlock *lock)
{
	fam_spin_lock_unpadded(&lock->__v__);
}

bool fam_spin_trylock(struct fam_spinlock *lock)
{
	return fam_spin_trylock_unpadded(&lock->__v__);
}

void fam_spin_unlock(struct fam_spinlock *lock)
{
	fam_spin_unlock_unpadded(&lock->__v__);
}
