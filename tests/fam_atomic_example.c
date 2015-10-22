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
#include <fam_atomic.h>

struct data {
	struct fam_atomic_64	atomic;
	struct fam_spinlock	spinlock;
};

int
main(int argc, char **argv) {
	char *file = "test.dat";
	int fd = open(file, O_CREAT | O_RDWR, 0666);
	unlink(file);
	ftruncate(fd, sizeof(struct data));
	struct data *data = mmap(0, sizeof(struct data),
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	fam_atomic_register_region(data, sizeof(struct data), fd, 0);

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

	/* Clean up */
	fam_atomic_unregister_region(data, sizeof(struct data));
	return 0;
}
