#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <asm/io.h>

struct fam_atomic_args_32 {
        int64_t offset;
        int32_t p32_0, p32_1;
};

struct fam_atomic_args_64 {
        int64_t offset;
        int64_t p64_0, p64_1;
};

struct fam_atomic_args_128 {
        int64_t offset;
        int64_t p128_0[2], p128_1[2];
};

#define DEVICE_NAME "fam_atomic"

#define _FAM_ATOMIC_MAGIC                       0xaa
#define _FAM_ATOMIC_32_FETCH_AND_ADD_NR         0x11
#define _FAM_ATOMIC_64_FETCH_AND_ADD_NR         0x12
#define _FAM_ATOMIC_32_SWAP_NR                  0x21
#define _FAM_ATOMIC_64_SWAP_NR                  0x22
#define _FAM_ATOMIC_128_SWAP_NR                 0x23
#define _FAM_ATOMIC_32_COMPARE_AND_STORE_NR     0x31
#define _FAM_ATOMIC_64_COMPARE_AND_STORE_NR     0x32
#define _FAM_ATOMIC_128_COMPARE_AND_STORE_NR    0x33
#define _FAM_ATOMIC_128_READ_NR                 0x43
#define _FAM_ATOMIC_WR(nr,type)                 _IOWR(_FAM_ATOMIC_MAGIC, (nr), type)
#define _FAM_ATOMIC_R(nr,type)                  _IOR(_FAM_ATOMIC_MAGIC, (nr), type)

/* temp = *offset; *offset += p0; p0 = temp */
#define FAM_ATOMIC_32_FETCH_AND_ADD             _FAM_ATOMIC_WR(_FAM_ATOMIC_32_FETCH_AND_ADD_NR, struct fam_atomic_args_32)
#define FAM_ATOMIC_64_FETCH_AND_ADD             _FAM_ATOMIC_WR(_FAM_ATOMIC_64_FETCH_AND_ADD_NR, struct fam_atomic_args_64)

/* temp = *offset; *offset = p0; p0 = temp; */
#define FAM_ATOMIC_32_SWAP                      _FAM_ATOMIC_WR(_FAM_ATOMIC_32_SWAP_NR, struct fam_atomic_args_32)
#define FAM_ATOMIC_64_SWAP                      _FAM_ATOMIC_WR(_FAM_ATOMIC_64_SWAP_NR, struct fam_atomic_args_64)
#define FAM_ATOMIC_128_SWAP                     _FAM_ATOMIC_WR(_FAM_ATOMIC_128_SWAP_NR, struct fam_atomic_args_128)

/* temp = *offset; if (temp == p0) *offset = p1; p0 = temp; */
#define FAM_ATOMIC_32_COMPARE_AND_STORE         _FAM_ATOMIC_WR(_FAM_ATOMIC_32_COMPARE_AND_STORE_NR, struct fam_atomic_args_32)
#define FAM_ATOMIC_64_COMPARE_AND_STORE         _FAM_ATOMIC_WR(_FAM_ATOMIC_64_COMPARE_AND_STORE_NR, struct fam_atomic_args_64)
#define FAM_ATOMIC_128_COMPARE_AND_STORE        _FAM_ATOMIC_WR(_FAM_ATOMIC_128_COMPARE_AND_STORE_NR, struct fam_atomic_args_128)

/* p0 = *offset */
#define FAM_ATOMIC_128_READ                     _FAM_ATOMIC_R(_FAM_ATOMIC_128_READ_NR, struct fam_atomic_args_128)

/* Base address to the atomic HSRs */
static void *atomic_base;
#define SIZEOF_ATOMIC_REGISTER	64000

/* Offset to result HSRs for each atomic operation */
#define CAS_OFFSET      0x330
#define FA_OFFSET       0x320
#define SWAP_OFFSET     0x310
#define READ_OFFSET     0x300

/* Offsets to the address/parameter HSRs */
#define P0_OFFSET       0X0
#define P1_OFFSET       0X100
#define ADDRESS_OFFSET  0x200

/*
 * These were the "old" offset values 
 * 
 * #define CAS_OFFSET		0xF0
 * #define FA_OFFSET		0xE0
 * #define SWAP_OFFSET		0xD0
 * #define READ_OFFSET		0xC0
 * #define P0_OFFSET		0X0
 * #define P1_OFFSET		0X40
 * #define ADDRESS_OFFSET	0x80
 */

extern uint64_t pa_to_lza(uint64_t pa);

int fam_atomic_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int fam_atomic_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 * Return -1 on error (no such page exists).
 */
static inline unsigned long va_to_pa(unsigned long virt_addr)
{
	unsigned long phys_addr, offset, pfn, address;
	struct mm_struct *mm = current->mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;

	offset = virt_addr % PAGE_SIZE;
	address = virt_addr - offset;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd))
		return -1;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return -1;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -1;

	ptep = pte_offset_map(pmd, address);
	pte = *ptep;

	if (!pte_present(pte))
		return -1;

	pfn = pte_pfn(pte);
	phys_addr = __pfn_to_phys(pfn) + offset;
	return phys_addr;
}

unsigned long zbridge_va_to_lza(unsigned long virt_addr)
{
	unsigned long phys_addr, lza;

	phys_addr = va_to_pa(virt_addr);
	if (phys_addr == -1) {
		return -1;
	}

	lza = pa_to_lza(phys_addr);

	return lza;
}

unsigned long lfs_offset_to_lza(int64_t offset)
{
	unsigned long lza;

	/*
	 * TODO: Eventually, we'll modify this function to have
	 * LFS translate the file offset to LZA. For now the LZA
	 * will just be the userspace VA to the atomic, so we'll
	 * manually do the va -> lza by walking the page tables
	 * and zbridge descriptor tables.
	 */
	lza = zbridge_va_to_lza((unsigned long)offset);

	return lza;
}

/*
static inline __uint128_t read128(__uint128_t *ptr)
{
	int64_t val1, val2;
	__uint128_t result;

        asm volatile("ldp %0, %1, [%2]"
		     : "=r" (val1), "=r" (val2)
		     : "r" (ptr)
		     : "memory");

	result = (__uint128_t)val1 | ((__uint128_t)val2<<64);
	return result;
}

static inline void write128(__uint128_t val, __uint128_t *ptr)
{
	int64_t val1, val2;

	val1 = (int64_t)val;
	val2 = (int64_t)(val >> 64);

        asm volatile("stp [%0], [%1], %2"
		     : "r" (val1), "r" (val2)
		     : "=r" (ptr)
		     : "memory");
}
*/

#define read128(ptr) 						\
({								\
	__uint128_t result;					\
	mb();							\
	result = *((volatile __uint128_t *)(ptr));		\
	mb();							\
	result;							\
})

#define write128(val, ptr)					\
({								\
	mb();							\
	*((volatile __uint128_t *)(ptr)) = (__uint128_t)(val);	\
	mb();							\
})

static int32_t zbridge_atomic_32(unsigned long lza, int32_t p32_0, int32_t p32_1,
				 unsigned int ioctl_num)
{
	void *atomic_register, *result_register;
	int32_t prev = 0;
	__uint128_t param0;

	preempt_disable();

	if (ioctl_num != FAM_ATOMIC_32_COMPARE_AND_STORE)
		p32_1 = 0;

	param0 = (__uint128_t)p32_0 << 96 | (__uint128_t)p32_1 << 32;

	atomic_register = atomic_base + (get_cpu() * SIZEOF_ATOMIC_REGISTER);
	write128(param0, atomic_register + P0_OFFSET);
	write128(lza, atomic_register + ADDRESS_OFFSET);

	switch (ioctl_num) {
	case FAM_ATOMIC_32_SWAP:
		result_register = atomic_register + SWAP_OFFSET;
		break;

	case FAM_ATOMIC_32_COMPARE_AND_STORE:
		result_register = atomic_register + CAS_OFFSET;
		break;

	case FAM_ATOMIC_32_FETCH_AND_ADD:
		result_register = atomic_register + FA_OFFSET;
		break;

	default:
		printk(KERN_DEBUG "ERROR: zbridge_atomic_32() invalid ioctl_num");
		return -1;
	}

	prev = readl(result_register);

	preempt_enable();

	return prev;
}

static int64_t zbridge_atomic_64(unsigned long lza, int64_t p64_0, int64_t p64_1,
				 unsigned int ioctl_num)
{
	void *atomic_register, *result_register;
	int64_t prev = 0;
	__uint128_t param0;

	preempt_disable();

	if (ioctl_num != FAM_ATOMIC_64_COMPARE_AND_STORE)
		p64_1 = 0;

	param0 = (__uint128_t)p64_0 << 64 | (__uint128_t)p64_1;

	atomic_register = atomic_base + (get_cpu() * SIZEOF_ATOMIC_REGISTER);
	write128(param0, atomic_register + P0_OFFSET);
	write128(lza, atomic_register + ADDRESS_OFFSET);

	switch (ioctl_num) {
	case FAM_ATOMIC_64_SWAP:
		result_register = atomic_register + SWAP_OFFSET;
		break;

	case FAM_ATOMIC_64_COMPARE_AND_STORE:
		result_register = atomic_register + CAS_OFFSET;
		break;

	case FAM_ATOMIC_64_FETCH_AND_ADD:
		result_register = atomic_register + FA_OFFSET;
		break;

	default:
		printk(KERN_DEBUG "ERROR: zbridge_atomic_64() invalid ioctl_num\n");
		return -1;
	}

	prev = readq(result_register);

	preempt_enable();

	return prev;
}

/*
 * Results of the atomic operation are stored in the "prev" array.
 */
static void zbridge_atomic_128(unsigned long lza, int64_t p128_0[2], int64_t p128_1[2],
			       int64_t prev[2], unsigned int ioctl_num)
{
	void *atomic_register, *result_register;
	__uint128_t result, param0, param1;

	preempt_disable();

	atomic_register = atomic_base + (get_cpu() * SIZEOF_ATOMIC_REGISTER);

	switch (ioctl_num) {
	case FAM_ATOMIC_128_SWAP:
		param0 = (__uint128_t)p128_0[1] << 64 | (__uint128_t)p128_0[0];
		write128(lza, atomic_register + ADDRESS_OFFSET);
		write128(param0, atomic_register + P0_OFFSET);
		result_register = atomic_register + SWAP_OFFSET;
		break;

	case FAM_ATOMIC_128_COMPARE_AND_STORE:
		param0 = (__uint128_t)p128_1[1] << 64 | (__uint128_t)p128_1[0];
		param1 = (__uint128_t)p128_0[1] << 64 | (__uint128_t)p128_0[0];
		write128(lza, atomic_register + ADDRESS_OFFSET);
		write128(param0, atomic_register + P0_OFFSET);
		write128(param1, atomic_register + P1_OFFSET);
		result_register = atomic_register + CAS_OFFSET;
		break;

	case FAM_ATOMIC_128_READ:
		write128(lza, atomic_register + ADDRESS_OFFSET);
		result_register = atomic_register + READ_OFFSET;
		break;

	default:
		printk(KERN_DEBUG "ERROR: zbridge_atomic_64() invalid ioctl_num\n");
		return;
	}

	result = read128((__uint128_t *)result_register);

	preempt_enable();

	prev[0] = ((uint64_t *)&result)[0];
	prev[1] = ((uint64_t *)&result)[1];
}

/*
 * Executes the atomic operation on a 32 bit zbridge atomic. The 'args_ptr'
 * parameter is the pointer to the user space data for the fam atomic operation.
 */
static int __ioctl_32(struct fam_atomic_args_32 *args_ptr, unsigned int ioctl_num)
{
	struct fam_atomic_args_32 args, result;
	unsigned long lza;
	int ret;

	ret = copy_from_user(&args, (void __user *)args_ptr, sizeof(args));
	if (ret)
		return -EFAULT;

	lza = lfs_offset_to_lza(args.offset);
	if (lza == (unsigned long)-1)
		return -EFAULT;

	result.p32_0 = zbridge_atomic_32(lza, args.p32_0, args.p32_1, ioctl_num);

	/*
	 * Write back results to user space.
	 */
	ret = copy_to_user(args_ptr, &result, sizeof(result));
	if (ret)
		return -EFAULT;

	return 0;
}

static int __ioctl_64(struct fam_atomic_args_64 *args_ptr, unsigned int ioctl_num)
{
	struct fam_atomic_args_64 args, result;
	unsigned long lza;
	int ret;

	ret = copy_from_user(&args, (void __user *)args_ptr, sizeof(args));
	if (ret)
		return -EFAULT;

	lza = lfs_offset_to_lza(args.offset);
	if (lza == (unsigned long)-1)
		return -EFAULT;

	result.p64_0 = zbridge_atomic_64(lza, args.p64_0, args.p64_1, ioctl_num);

	ret = copy_to_user(args_ptr, &result, sizeof(result));
	if (ret)
		return -EFAULT;

	return 0;
}

static int __ioctl_128(struct fam_atomic_args_128 *args_ptr, unsigned int ioctl_num)
{
	struct fam_atomic_args_128 args, result;
	unsigned long lza;
	int ret;
	int64_t prev[2];

	prev[0] = prev[1] = 0;

	ret = copy_from_user(&args, (void __user *)args_ptr, sizeof(args));
	if (ret)
		return -EFAULT;

	lza = lfs_offset_to_lza((unsigned long)args.offset);
	if (lza == (unsigned long)-1)
		return -EFAULT;

	zbridge_atomic_128(lza, args.p128_0, args.p128_1, prev, ioctl_num);

	result.p128_0[0] = prev[0];
	result.p128_0[1] = prev[1];

	ret = copy_to_user(args_ptr, &result, sizeof(result));
	if (ret)
		return -EFAULT;

	return 0;
}

/*
 * Main call into the GenZ atomic driver from user space.
 */
long fam_atomic_ioctl(struct file *file, unsigned int ioctl_num, unsigned long arg)
{
	int ret = 0;

	switch (ioctl_num) {

	case FAM_ATOMIC_32_SWAP:
		ret = __ioctl_32((struct fam_atomic_args_32 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_32_COMPARE_AND_STORE:
		ret = __ioctl_32((struct fam_atomic_args_32 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_32_FETCH_AND_ADD:
		ret = __ioctl_32((struct fam_atomic_args_32 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_64_FETCH_AND_ADD:
		ret = __ioctl_64((struct fam_atomic_args_64 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_64_SWAP:
		ret = __ioctl_64((struct fam_atomic_args_64 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_64_COMPARE_AND_STORE:
		ret = __ioctl_64((struct fam_atomic_args_64 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_128_SWAP:
		ret = __ioctl_128((struct fam_atomic_args_128 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_128_COMPARE_AND_STORE:
		ret = __ioctl_128((struct fam_atomic_args_128 *)arg, ioctl_num);
		break;

	case FAM_ATOMIC_128_READ:
		ret = __ioctl_128((struct fam_atomic_args_128 *)arg, ioctl_num);
		break;

	default:
		printk(KERN_INFO "error: fam_atomic_ioctl: invalid ioctl_num\n");
		ret = -1;
		break;
	}

	return ret;
}

struct file_operations Fops = {
	.open = fam_atomic_open,
	.release = fam_atomic_release,
	.unlocked_ioctl = fam_atomic_ioctl,
};

struct cdev c_dev;
static struct class *cl;
static dev_t first;

static int fam_atomic_init(void)
{
	if (alloc_chrdev_region(&first, 0, 1, DEVICE_NAME) < 0) {
		printk(KERN_INFO "alloc_chrdev_region error\n");
		return -1;
	}

	cdev_init(&c_dev, &Fops);
	if (cdev_add(&c_dev, first, 1) == -1) {
		device_destroy(cl, first);
		unregister_chrdev_region(first, 1);
		printk(KERN_INFO "cdev_add error\n");
		return -1;
	}

	cl = class_create(THIS_MODULE, "fam_atomic_class");
	if (IS_ERR(cl)) {
		unregister_chrdev_region(first, 1);
		printk(KERN_INFO "class_create error\n");
		return -1;
	}

	if (device_create(cl, NULL, first, NULL, DEVICE_NAME) == NULL) {
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		printk(KERN_INFO "device_create error\n");
		return -1;
	}

	atomic_base = (void *)ioremap(0xEFB60000000, 67108863);

	return 0;
}

static void fam_atomic_exit(void)
{
	device_destroy(cl, first);
	class_destroy(cl);
	cdev_del(&c_dev);

	/* 
	 * Unregister the device 
	 */
	unregister_chrdev_region(first, 1);

	printk(KERN_INFO "Cleaning up module.\n");
}

module_init(fam_atomic_init);
module_exit(fam_atomic_exit);
MODULE_LICENSE("GPL");
