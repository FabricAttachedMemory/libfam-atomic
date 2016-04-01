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
#include <time.h>

static inline void
acquire_compare_and_store_32(struct fam_atomic_32 *atomic)
{
	for (;;) {
		if (fam_atomic_32_compare_and_store(atomic, 0, 1) == 0)
			break;
	}
}

static inline void
release_compare_and_store_32(struct fam_atomic_32 *atomic)
{
	fam_atomic_32_write(atomic, 0);
}

static inline void
acquire_compare_and_store_64(struct fam_atomic_64 *atomic)
{
	for (;;) {
		if (fam_atomic_64_compare_and_store(atomic, 0, 1) == 0)
			break;
	}
}

static inline void
release_compare_and_store_64(struct fam_atomic_64 *atomic)
{
	fam_atomic_64_write(atomic, 0);
}

static inline void
acquire_swap_32(struct fam_atomic_32 *atomic)
{
	for (;;) {
		if (!fam_atomic_32_swap(atomic, 1))
			break;
	}
}

static inline void
release_swap_32(struct fam_atomic_32 *atomic)
{
	fam_atomic_32_write(atomic, 0);
}

static inline void
acquire_swap_64(struct fam_atomic_64 *atomic) 
{
	for (;;) {
		if (!fam_atomic_64_swap(atomic, 1))
			break;
	}
}

static inline void
release_swap_64(struct fam_atomic_64 *atomic)
{
	fam_atomic_64_write(atomic, 0);
}

/*
 * This is the main data structure containing regular variables
 * that get modified by multiple processes, and fam_atomics which
 * synchronizes access to those variables.
 */
struct data {
	struct fam_atomic_32 compare_store_32;
	struct fam_atomic_64 compare_store_64;
	struct fam_atomic_32 swap_32;
	struct fam_atomic_64 swap_64;
};

struct benchmark_data {
	int64_t w1;
	int64_t w2;
	int64_t w3;
	int64_t w4;
	int start;
	int done;
	int64_t total_iterations;
};

int main(int argc, char **argv)
{
	char *file = "/lfs/fam_atomic_test.data";
	struct data *data;
	struct benchmark_data *benchmark_data;
	int i;
	int test_duration_sec = 20;
	int nr_process = 10;
	int pid;
	int fd, fd_benchmark;

	fd = open(file, O_CREAT | O_RDWR, 0666);

	if (fd < 0) {
		fprintf(stderr, "ERROR: Unable to open LFS file\n");
		return 1;
	}

	unlink(file);
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

	fd_benchmark = open("fam_atomic_benchmark.data", O_CREAT | O_RDWR, 0666);
	unlink("fam_atomic_benchmark.data");
	ftruncate(fd_benchmark, sizeof(int64_t));
	benchmark_data = mmap(0, sizeof(int64_t), PROT_READ | PROT_WRITE,
						  MAP_SHARED, fd_benchmark, 0);

	benchmark_data->w1 = 0;
	benchmark_data->w2 = 0;
	benchmark_data->w3 = 0;
	benchmark_data->w4 = 0;
	fam_atomic_32_write(&data->compare_store_32, 0);
	fam_atomic_64_write(&data->compare_store_64, 0);
	fam_atomic_32_write(&data->swap_32, 0);
	fam_atomic_64_write(&data->swap_64, 0);
	__sync_lock_test_and_set(&benchmark_data->start, 0);
	__sync_lock_test_and_set(&benchmark_data->done, 0);
	benchmark_data->total_iterations = 0;

	__sync_synchronize();

	printf("\nRunning single node fam atomic test:\n\n");

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
		__sync_lock_test_and_set(&benchmark_data->start, 1);

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
		__sync_lock_test_and_set(&benchmark_data->done, 1);

		/*
		 * Make sure all processes really finished.
		 */
		while (wait(NULL) >= 0);

		__sync_synchronize();

		/*
		 * Verify all words in the region are 0 and print whether or not
		 * the test completed successfully.
		 */
		if (benchmark_data->w1 == (benchmark_data->total_iterations) &&
		    benchmark_data->w2 == (benchmark_data->total_iterations) &&
		    benchmark_data->w3 == (benchmark_data->total_iterations) &&
		    benchmark_data->w4 == (benchmark_data->total_iterations)) {
			printf("\n\nTest completed successfully!\n\n");
			return 0;
		} else {
			printf("\n\nERROR: Test failed\n\n");
			return -1;
		}
	}

	/*
	 * All created processes, excluding the main process will enter
	 * this code path. Here, we wait until all processes have been
	 * created so that they all begin the test at the same time. The
	 * "main" process will signal this by setting data->start.
	 */
	while (!__sync_fetch_and_add(&benchmark_data->start, 0))
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
		__sync_fetch_and_add(&benchmark_data->total_iterations, 1);

		/*
		 * compare and store 32.
		 */
		acquire_compare_and_store_32(&data->compare_store_32);
		benchmark_data->w1 += 1;
		release_compare_and_store_32(&data->compare_store_32);

		/*
		 * compare and store 64.
		 */
		acquire_compare_and_store_64(&data->compare_store_64);
		benchmark_data->w2 += 1;
		release_compare_and_store_64(&data->compare_store_64);

		/*
		 * swap 32.
		 */
		acquire_swap_32(&data->swap_32);
		benchmark_data->w3 += 1;
		release_swap_32(&data->swap_32);

		/*
		 * swap 64.
		 */
		acquire_swap_64(&data->swap_64);
		benchmark_data->w4 += 1;
		release_swap_64(&data->swap_64);
	}

	fam_atomic_unregister_region(data, sizeof(struct data));

	return 0;
}

