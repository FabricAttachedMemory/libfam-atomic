/*
 * Copyright © 2015, Hewlett Packard Enterprise Development LP
 *
 * Author: Keith Packard <packard@hpe.com>
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

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fam_atomic.h>

/*
 * Structure containing all unpadded fam atomics
 * and locks. The structure is cacheline aligned
 * so that it would not share cachelines with
 * regular data.
 */
struct node {
	/* unpadded 32 bit fam atomics */
	int32_t fam_atomic_val1;
	int32_t fam_atomic_val2;

	/* unpadded 64 bit fam atomics */
	int64_t fam_atomic_val3;
	int64_t fam_atomic_val4;

	/* unpadded fam spinlocks */
	struct fam_spinlock_unpadded spinlock1;
	struct fam_spinlock_unpadded spinlock2;
} __attribute__((__aligned__(64)));

struct data {
	/*
	 * Regular fam atomic and fam spinlock.
	 * Each takes up an entire cacheline.
	 */
	struct fam_atomic_64	atomic;
	struct fam_spinlock	spinlock;

	/*
	 * Group of unpadded fam atomics and locks. If we
	 * have a lot of atomics, we can save space by using
	 * the unpadded variant and pack all of them into
	 * the same cacheline.
	 */
	struct node		node;
};

int
main(int argc, char **argv) {
	char *file = "test.dat";
	int fd = open(file, O_CREAT | O_RDWR, 0666);
	unlink(file);
	ftruncate(fd, sizeof(struct data));
	struct data *data = mmap(0, sizeof(struct data),
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	/*
	 * We must register the region with the fam atomic library
	 * before the fam atomics and locks within the region can be used.
	 */
	if (fam_atomic_register_region(data, sizeof(struct data), fd, 0) == -1) {
		fprintf(stderr, "unable to register atomic region\n");
		return 1;
	}

	/* Set to zero */
	fam_atomic_64_write(&data->atomic, 0);

	/* Swap with 12, make sure previous was zero */
	int64_t prev = fam_atomic_64_fetch_and_add(&data->atomic, 12);
	assert(prev == 0);

	/* Make sure value is now 12 */
	int64_t next = fam_atomic_64_read(&data->atomic);
	assert(next == 12);

	/* Initialize spinlock */
	data->spinlock = FAM_SPINLOCK_INITIALIZER;

	/* Lock it */
	fam_spin_lock(&data->spinlock);

	/* Make sure trylock fails now */
	bool trylock_locked = fam_spin_trylock(&data->spinlock);
	assert(!trylock_locked);

	/* Unlock */
	fam_spin_unlock(&data->spinlock);

	/* Make sure trylock succeeds now */
	bool trylock_unlocked = fam_spin_trylock(&data->spinlock);
	assert(trylock_unlocked);

	/* Unlock */
	fam_spin_unlock(&data->spinlock);

	/* Initialize unpadded atomics and locks */
	fam_atomic_32_write_unpadded(&data->node.fam_atomic_val1, 0);
	fam_atomic_32_write_unpadded(&data->node.fam_atomic_val2, 0);
	fam_atomic_64_write_unpadded(&data->node.fam_atomic_val3, 0);
	fam_atomic_64_write_unpadded(&data->node.fam_atomic_val4, 0);
	data->node.spinlock1 = FAM_SPINLOCK_UNPADDED_INITIALIZER;
	data->node.spinlock2 = FAM_SPINLOCK_UNPADDED_INITIALIZER;

	/* Acquire unpadded fam spinlocks */
	fam_spin_lock_unpadded(&data->node.spinlock1);
	assert(fam_spin_trylock_unpadded(&data->node.spinlock2));

	/* Release unpadded fam spinlocks */
	fam_spin_unlock_unpadded(&data->node.spinlock2);
	fam_spin_unlock_unpadded(&data->node.spinlock1);

	/* Clean up */
	fam_atomic_unregister_region(data, sizeof(struct data));
	return 0;
}
