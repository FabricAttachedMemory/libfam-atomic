#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <libgen.h>
#include <fam_atomic.h>

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

struct data {
	int64_t w1;
	int64_t w2;
	int64_t w3;
	int64_t w4;
	struct fam_atomic_32 compare_store_32;
	struct fam_atomic_64 compare_store_64;
	struct fam_atomic_32 swap_32;
	struct fam_atomic_64 swap_64;
	bool start;
	int64_t total_iterations;
};

int main(int argc, char **argv)
{
	int nr_increments = 2000000;
	struct data *data;
	int i;
	int nr_process = 10;
	int pid;

	int fd = open("fam_atomic_test.data", O_CREAT | O_RDWR, 0666);
	ftruncate(fd, sizeof(struct data));
	data = mmap(0, sizeof(struct data), PROT_READ | PROT_WRITE,
		   			    MAP_SHARED, fd, 0);

	/*
	 * Register the region as an fam-atomic region after the mmap.
	 */
	if (fam_atomic_register_region(data, sizeof(struct data), 0, 0)) {
		fprintf(stderr, "unable to register atomic region\n");
		return 3;
	}

	data->w1 = 0;
	data->w2 = 0;
	data->w3 = 0;
	data->w4 = 0;
	fam_atomic_32_write(&data->compare_store_32, 0);
	fam_atomic_64_write(&data->compare_store_64, 0);
	fam_atomic_32_write(&data->swap_32, 0);
	fam_atomic_64_write(&data->swap_64, 0);
	data->start = false;
	data->total_iterations = 0;

	__sync_synchronize();

	printf("\nRunning single node fam atomic test:\n\n");

	for (i = 0; i < nr_process; i++) {
		pid = fork();
		if (pid == 0) {
			break;
		}
	}

	/*
	 * The main process will wait until the rest of the processes
	 * finish running the tests. It will print the current status
	 * of the run, as well as report whether or not the test
	 * was succesful.
	 */
	if (pid != 0) {
		int i;
		int line_length = 52;

		/*
		 * All processes have been created. Signal the other
		 * processes to start test.
		 */
		data->start = true;

		while (data->total_iterations < nr_increments * nr_process) {
			sleep(1);

			double percent_done = (double)data->total_iterations /
					      (nr_increments * nr_process) *
					      line_length;

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
	
			printf("] %.2f%%\r", (double)data->total_iterations /
					     (nr_increments * nr_process) * 100);
			fflush(stdout);
		}

		/*
		 * Make sure all processes really finished.
		 */
		while (wait(NULL) >= 0);

		/*
		 * Verify all words in the region is 0.
		 */
		if (data->w1 == (nr_process * nr_increments) &&
		    data->w2 == (nr_process * nr_increments) &&
		    data->w3 == (nr_process * nr_increments) &&
		    data->w4 == (nr_process * nr_increments)) {
			printf("\n\nTest completed successfully!\n\n",
			       basename(argv[0]));
			return 0;
		} else {
			printf("\n\nERROR: Test failed\n\n", basename(argv[0]));
			return -1;
		}
	}

	/*
	 * Wait until all other processes have been created so that they
	 * all begin the test t the same time. The "main" process will
	 * signal this by setting data->start.
	 */
	while (!data->start);

	for (i = 0; i < nr_increments; i++) {
		/*
		 * The total_iterations variable just keeps track
		 * of the progress of the test and isn't really part of
		 * the test itself, so just use the regular fetch_and_add().
		*/
		__sync_fetch_and_add(&data->total_iterations, 1);

		/*
		 * compare and store 32.
		 */
		acquire_compare_and_store_32(&data->compare_store_32);
		data->w1 += 1;
		release_compare_and_store_32(&data->compare_store_32);

		/*
		 * compare and store 64.
		 */
		acquire_compare_and_store_64(&data->compare_store_64);
		data->w2 += 1;
		release_compare_and_store_64(&data->compare_store_64);

		/*
		 * swap 32.
		 */
		acquire_swap_32(&data->swap_32);
		data->w3 += 1;
		release_swap_32(&data->swap_32);

		/*
		 * swap 64.
		 */
		acquire_swap_64(&data->swap_64);
		data->w4 += 1;
		release_swap_64(&data->swap_64);
	}

	fam_atomic_unregister_region(data, sizeof(struct data));

	return 0;
}

