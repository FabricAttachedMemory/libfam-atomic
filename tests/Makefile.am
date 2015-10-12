
noinst_PROGRAMS = fam_atomic_single_node_test fam_atomic_example

TESTS=$(noinst_PROGRAMS)

TEST_LDADD=../libfam_atomic.la

AM_CPPFLAGS = -I$(top_srcdir)

fam_atomic_single_node_test_LDADD=$(TEST_LDADD)

fam_atomic_example_LDADD=$(TEST_LDADD)
