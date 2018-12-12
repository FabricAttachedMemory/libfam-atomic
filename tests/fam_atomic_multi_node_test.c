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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <libgen.h>
#include <fam_atomic.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Make this a non-zero value so in cases where the atomic
 * operation incorrectly returns 0, we don't treat the
 * operation as return successfully.
 */
#define AVAILABLE (1<<16)
#define ACQUIRED  (AVAILABLE + 1)

static inline void
acquire_compare_and_store_32(int32_t *atomic)
{
	for (;;) {
		if (fam_atomic_32_compare_store(atomic, AVAILABLE, ACQUIRED) == AVAILABLE)
			break;
	}
}

static inline void
release_compare_and_store_32(int32_t *atomic)
{
	(void) fam_atomic_32_fetch_add(atomic, -1);
}

static inline void
acquire_compare_and_store_64(int64_t *atomic)
{
	for (;;) {
		if (fam_atomic_64_compare_store(atomic, AVAILABLE, ACQUIRED) == AVAILABLE)
			break;
	}
}

static inline void
release_compare_and_store_64(int64_t *atomic)
{
	(void) fam_atomic_64_fetch_add(atomic, -1);
}

static inline void
acquire_swap_32(int32_t *atomic)
{
	for (;;) {
		if (fam_atomic_32_swap(atomic, ACQUIRED) == AVAILABLE)
			break;
	}
}

static inline void
release_swap_32(int32_t *atomic)
{
	(void) fam_atomic_32_fetch_add(atomic, -1);
}

static inline void
acquire_swap_64(int64_t *atomic) 
{
	for (;;) {
		if (fam_atomic_64_swap(atomic, ACQUIRED) == AVAILABLE)
			break;
	}
}

static inline void
release_swap_64(int64_t *atomic)
{
	(void) fam_atomic_64_fetch_add(atomic, -1);
}

static inline void
acquire_compare_and_store_128(int64_t *atomic)
{
        int64_t compare[2];
        int64_t store[2];
        int64_t result[2];

        compare[0] = compare[1] = AVAILABLE;
        store[0] = store[1] = ACQUIRED;

        for (;;) {
                fam_atomic_128_compare_store(atomic, compare, store, result);

                if (result[0] == compare[0] && result[1] == compare[1])
                        break;
        }
}

static inline void
release_compare_and_store_128(int64_t *atomic)
{
	int64_t compare[2];
	int64_t store[2];
	int64_t result[2];

	/*
	 * We purposely implement the release function by decrementing
	 * the atomic value instead of setting it to the available state.
	 * The effect of this is that a deadlock occurs if there are bugs
	 * with the atomic, and the user can know something went wrong with
	 * the test.
	 */
	for (;;) {
		fam_atomic_128_read(atomic, compare);

		store[0] = compare[0] - 1;
		store[1] = compare[1] - 1;

		fam_atomic_128_compare_store(atomic, compare, store, result);

		if (result[0] == compare[0] && result[1] == compare[1])
			break;
	}
}

static inline void
acquire_swap_128(int64_t *atomic) 
{
        int64_t value[2];
        int64_t result[2];

        value[0] = value[1] = ACQUIRED;

        for (;;) {
                fam_atomic_128_swap(atomic, value, result);

                if (result[0] == AVAILABLE && result[1] == AVAILABLE)
                        break;
        }
}

static inline void
release_swap_128(int64_t *atomic)
{
	int64_t compare[2];
	int64_t store[2];
	int64_t result[2];

	/*
	 * We purposely implement the release function by decrementing
	 * the atomic value instead of setting it to the available state.
	 * The effect of this is that a deadlock occurs if there are bugs
	 * with the atomic, and the user can know something went wrong with
	 * the test.
	 */
	for (;;) {
		fam_atomic_128_read(atomic, compare);

		store[0] = compare[0] - 1;
		store[1] = compare[1] - 1;

		fam_atomic_128_compare_store(atomic, compare, store, result);

		if (result[0] == compare[0] && result[1] == compare[1])
			break;
	}
}

/*
 * This is the main data structure containing regular variables
 * that get modified by multiple processes, and fam_atomics which
 * synchronizes access to those variables.
 */
struct data {
	int32_t compare_store_32;
	int64_t compare_store_64;
	int32_t swap_32;
	int64_t swap_64;
	int32_t fetch_add_32;
	int64_t fetch_add_64;
	int64_t compare_store_128[2];
	int64_t swap_128[2];
} __attribute__((__aligned__(128)));

/*
 * This structure contains data for managing the benchmark.
 */
struct benchmark_data {
	int64_t iterations;
	bool start;
	int32_t done;
};

bool file_exists(char *filename)
{
	struct stat buffer;

	if (stat(filename, &buffer) == 0)
		return true;

	return false;
}

int main(int argc, char **argv)
{
	char *file = "/lfs/fam_atomic_mult_node_test.data";
	struct data *data;
	int i;
	int test_duration_sec = 20;
	int nr_process = 1;
	int pid;
	int fd;
	bool need_init = false;

	if (!file_exists(file))
		need_init = true;

	fd = open(file, O_CREAT | O_RDWR, 0666);

	if (fd < 0) {
		fprintf(stderr, "ERROR: Unable to open LFS file\n");
		return 1;
	}

	ftruncate(fd, sizeof(struct data));
	data = mmap(0, sizeof(struct data), PROT_READ | PROT_WRITE,
		   			    MAP_SHARED, fd, 0);

	/*
	 * Register the region as an fam-atomic region after the mmap operation.
	 */
	if (fam_atomic_register_region(data, sizeof(struct data), fd, 0)) {
		fprintf(stderr, "unable to register atomic region\n");
		return 3;
	}

	if (need_init) {
		int64_t value[2] = { AVAILABLE, AVAILABLE };

		fam_atomic_32_write(&data->compare_store_32, AVAILABLE);
		fam_atomic_64_write(&data->compare_store_64, AVAILABLE);
		fam_atomic_32_write(&data->swap_32, AVAILABLE);
		fam_atomic_64_write(&data->swap_64, AVAILABLE);
		fam_atomic_32_write(&data->fetch_add_32, 0);
		fam_atomic_64_write(&data->fetch_add_64, 0);
		fam_atomic_128_write(data->compare_store_128, value);
		fam_atomic_128_write(data->swap_128, value);
	}

	struct benchmark_data *benchmark_data;
	int fd_benchmark = open("fam_atomic_iterations.data", O_CREAT | O_RDWR, 0666);
	unlink("fam_atomic_iterations.data");
	ftruncate(fd_benchmark, sizeof(struct benchmark_data));
	benchmark_data = mmap(0, sizeof(struct benchmark_data), PROT_READ | PROT_WRITE,
		   				  MAP_SHARED, fd_benchmark, 0);
	benchmark_data->iterations = 0;
	benchmark_data->start = false;
	benchmark_data->done = false;

	__sync_synchronize();

	printf("First 2 words in region are: %lld, %lld\n",
	       (long long)fam_atomic_32_read(&data->fetch_add_32),
	       (long long)fam_atomic_64_read(&data->fetch_add_64));

	printf("\nRunning multi node fam atomic test:\n\n");

	/*
	 * Create nr_process to run the tests.
	 */
	for (i = 0; i < nr_process; i++) {
		pid = fork();
		if (pid == 0) {
			break;
		}
	}

	/*
	 * The main process will wait until the rest of the processes
	 * finish running the actual test. It will print the current
	 * status of the run, and report whether or not the test was
	 * successful when the test completes.
	 */
	if (pid != 0) {
		struct timespec start, now;
		int curr_duration_sec;
		int i;
		int line_length = 52;

		/*
		 * All processes have been created. Signal the other
		 * processes to start test.
		 */
		__sync_lock_test_and_set(&benchmark_data->start, true);

		clock_gettime(CLOCK_MONOTONIC_COARSE, &start);

		for (;;) {
			double percent_done;
			int duration_curr_sec;

			clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
			curr_duration_sec = now.tv_sec - start.tv_sec;
			if (curr_duration_sec > test_duration_sec)
				break;

			sleep(1);

			percent_done = (double)curr_duration_sec / test_duration_sec * line_length;
			printf("   [");

			for (i = 1; i <= line_length; i++) {
				if (percent_done < 2)
					percent_done = 2;

				if (i == 1)
					printf("<");
				else if (i == (int)percent_done)
					printf(">");
				else if (i < (int)percent_done)
					printf("=");
				else
					printf(" ");
			}
	
			printf("] %.2f%%\r", (double)curr_duration_sec / test_duration_sec * 100);
			fflush(stdout);
		}

		/*
		 * Notify all other processes that the benchmark is complete.
		 */
		__sync_lock_test_and_set(&benchmark_data->done, true);

		/*
		 * Make sure all processes really finished.
		 */
		while (wait(NULL) >= 0);

		__sync_synchronize();

		printf("\nIterations = %lld\n", (long long)benchmark_data->iterations);
		printf("Test completed: %lld, %lld\n",
		       (long long)fam_atomic_32_read(&data->fetch_add_32),
		       (long long)fam_atomic_64_read(&data->fetch_add_64));

		return 0;
	}

	/*
	 * All created processes, excluding the main process will enter
	 * this code path. Here, we wait until all processes have been
	 * created so that they all begin the test at the same time. The
	 * "main" process will signal this by setting data->start.
	 */
	while (!benchmark_data->start)
		usleep(100 * 1000);

	for (;;) {
		/* Use fetch_and_add 0 as atomic read. */
		if (__sync_fetch_and_add(&benchmark_data->done, 0) == 1)
			break;

		/*
		 * The total_iterations variable just keeps track
		 * of the progress of the test and isn't really part of
		 * the test itself, so just use the regular fetch_and_add().
		*/
		__sync_fetch_and_add(&benchmark_data->iterations, 1);

		/*
		 * compare and store 32.
		 */
		acquire_compare_and_store_32(&data->compare_store_32);
		release_compare_and_store_32(&data->compare_store_32);

		/*
		 * compare and store 64.
		 */
		acquire_compare_and_store_64(&data->compare_store_64);
		release_compare_and_store_64(&data->compare_store_64);

		/*
		 * swap 32.
		 */
		acquire_swap_32(&data->swap_32);
		release_swap_32(&data->swap_32);

		/*
		 * swap 64.
		 */
		acquire_swap_64(&data->swap_64);
		release_swap_64(&data->swap_64);

		/*
		 * compare and store 128.
		 */
		acquire_compare_and_store_128(data->compare_store_128);
		release_compare_and_store_128(data->compare_store_128);

		/*
		 * swap 128.
		 */
		acquire_swap_128(data->swap_128);
		release_swap_128(data->swap_128);

		fam_atomic_32_fetch_add(&data->fetch_add_32, 1);
		fam_atomic_64_fetch_add(&data->fetch_add_64, 1);
	}

	fam_atomic_unregister_region(data, sizeof(struct data));

	return 0;
}
