SUFFIXES = .txt .3

DOC_FILES= \
	fam_atomic.txt \
	fam_atomic_128_compare_store.txt \
	fam_atomic_128_read.txt \
	fam_atomic_128_swap.txt \
	fam_atomic_128_write.txt \
	fam_atomic_32_compare_store.txt \
	fam_atomic_32_fetch_add.txt \
	fam_atomic_32_fetch_and.txt \
	fam_atomic_32_fetch_or.txt \
	fam_atomic_32_fetch_xor.txt \
	fam_atomic_32_read.txt \
	fam_atomic_32_swap.txt \
	fam_atomic_32_write.txt \
	fam_atomic_64_compare_store.txt \
	fam_atomic_64_fetch_add.txt \
	fam_atomic_64_fetch_and.txt \
	fam_atomic_64_fetch_or.txt \
	fam_atomic_64_fetch_xor.txt \
	fam_atomic_64_read.txt \
	fam_atomic_64_swap.txt \
	fam_atomic_64_write.txt \
	fam_atomic_register_region.txt \
	fam_atomic_unregister_region.txt \
	fam_spin_lock.txt \
	fam_spin_trylock.txt \
	fam_spin_unlock.txt

man_MANS = $(DOC_FILES:.txt=.3)

CLEANFILES = $(man_MANS)
EXTRA_DIST = $(DOC_FILES)

.txt.3:
	a2x -L -d manpage -f manpage -D . $(srcdir)/$*.txt

fam_atomic.3: ../tests/fam_atomic_example.c
