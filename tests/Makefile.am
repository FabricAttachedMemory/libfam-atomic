
bin_PROGRAMS = fam_atomic_example fam_atomic_single_node_test fam_atomic_multi_node_test

# TESTS=$(noinst_PROGRAMS)

# TEST_LDADD=../libfam_atomic.la

AM_CPPFLAGS = -I$(top_srcdir)

fam_atomic_example_LDADD=../libfam_atomic.la

fam_atomic_single_node_test_LDADD=../libfam_atomic.la
fam_atomic_single_node_test_LDFLAGS = -pthread

fam_atomic_multi_node_test_LDADD=../libfam_atomic.la
fam_atomic_multi_node_test_LDFLAGS = -pthread
