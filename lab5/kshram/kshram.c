/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/pfn.h>
#include <linux/mm.h>
#include "kshram.h"

#define MAX_SIZE 4096

struct dev_info {
	int size;
	void* mem_ptr;
};

static dev_t devnum;
static struct cdev c_dev[8];
static struct class *clazz;
static struct dev_info kshram[8];
static int major;
static int dev_no;
static int ret;
static unsigned long len;
static unsigned long pfn;

static int kshram_dev_open(struct inode *i, struct file *f) {
	
	sscanf(f->f_path.dentry->d_iname, "kshram%d", &dev_no);
	// printk(KERN_INFO "kshram: device %d opened.\n", dev_no);

	f->private_data = kshram[dev_no].mem_ptr;
	return 0;
}

static int kshram_dev_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "kshram: device closed.\n");
	sscanf(f->f_path.dentry->d_iname, "kshram%d", &dev_no);

	// printk(KERN_INFO "kshram: device %d closed.\n", dev_no);
	f->private_data = NULL;
	// kfree(f->private_data);
	return 0;
}

static ssize_t kshram_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "kshram: read %zu bytes @ %llu.\n", len, *off);
	memcpy(buf, (char*)f->private_data + *off, len);
	return len;
}

static ssize_t kshram_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "kshram: write %zu bytes @ %llu.\n", len, *off);
	memcpy((char*)f->private_data + *off, buf, len);
	return len;
}

static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "kshram: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	sscanf(fp->f_path.dentry->d_iname, "kshram%d", &dev_no);

	if(cmd == KSHRAM_GETSLOTS){
		// printk(KERN_INFO "ioctl: GETSLOTS\n");
		return 8;
	}else if(cmd == KSHRAM_GETSIZE){
		// printk(KERN_INFO "ioctl: GETSIZE\n");
		
		return kshram[dev_no].size;

	}else if(cmd == KSHRAM_SETSIZE){
		// printk(KERN_INFO "ioctl: SETSIZE\n");
		kshram[dev_no].size = arg;
		kshram[dev_no].mem_ptr = krealloc(kshram[dev_no].mem_ptr, kshram[dev_no].size, GFP_KERNEL);

		// for(int j = 0; j < len; j += PAGE_SIZE)
		// 	SetPageReserved(virt_to_page((long long int*)(kshram[dev_no].mem_ptr) + j));

		fp->private_data = kshram[dev_no].mem_ptr;

		return kshram[dev_no].size;
	}
	return 0;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct* vma){
	struct page* pg;

	sscanf(fp->f_path.dentry->d_iname, "kshram%d", &dev_no);

	printk(KERN_INFO "kshram/mmap: idx %d size %d\n", dev_no, kshram[dev_no].size);

	pg = virt_to_page(kshram[dev_no].mem_ptr);
	// printk(KERN_INFO "virtual to page\n");

	pfn = page_to_pfn(pg);
	// printk(KERN_INFO "kshram/mmap: page num: %lu\n", pfn);

	len = vma->vm_end - vma->vm_start;

	// printk(KERN_INFO "kshram/mmap: vma len: %lu\n", len);

	ret = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
	// printk(KERN_INFO "kshram/mmap: remapping\n");

	if(ret < 0){
		pr_err("Could not map the address area\n");
		return -EIO;
	}else{
		// kshram[dev_no].size = len;
		// kshram[dev_no].mem_ptr = krealloc(kshram[dev_no].mem_ptr, kshram[dev_no].size, GFP_KERNEL);

		// for(int j = 0; j < len; j += PAGE_SIZE)
		// 	SetPageReserved(virt_to_page((long long int*)(kshram[dev_no].mem_ptr) + j));

		// fp->private_data = kshram[dev_no].mem_ptr;

		return 0;
	}
	 
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.read = kshram_dev_read,
	.write = kshram_dev_write,
	.unlocked_ioctl = kshram_dev_ioctl,
	.release = kshram_dev_close,
	.mmap = kshram_dev_mmap
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	char buf[] = "`Kshram!` in /proc.\n";
	for(int i = 0; i < 8; i++){
		printk(KERN_INFO "0%d: %d\n", i, kshram[i].size);
	}
	seq_printf(m, buf);
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *fp) {
	return single_open(fp, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{
	dev_t new_dev;

	if(alloc_chrdev_region(&devnum, 0, 8, "updev") < 0)
			return -1;

	if((clazz = class_create(THIS_MODULE, "upclass")) == NULL)
			goto release_region;

	clazz->devnode = kshram_devnode;
	
	major = MAJOR(devnum);

    for(int i = 0; i < 8; i++){
		// create char dev
		
		new_dev = MKDEV(major, i);

        if(device_create(clazz, NULL, new_dev, NULL, "kshram%d", i) == NULL)
		    goto release_class;

		cdev_init(&c_dev[i], &kshram_dev_fops);

		if(cdev_add(&c_dev[i], new_dev, 1) == -1)
			goto release_device;

		kshram[i].size = 4096;

		kshram[i].mem_ptr = kzalloc(kshram[i].size, GFP_KERNEL);

		SetPageReserved(virt_to_page((long long int*)(kshram[i].mem_ptr)));

		printk(KERN_INFO "kshram%d: %d bytes allocated @ %llx\n", i, kshram[i].size, (unsigned long long int)kshram[i].mem_ptr);

    }

	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	
	
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
	
release_class:
	class_destroy(clazz);

release_region:
	unregister_chrdev_region(devnum, 1);

	return -1;
}

static void __exit kshram_cleanup(void)
{
	dev_t destroy_dev;
	remove_proc_entry("kshram", NULL);
	
	major = MAJOR(devnum);

	for(int i = 0; i < 8; i++){

		// for(int j = 0; j < kshram[i].size; j += PAGE_SIZE)
		// 	ClearPageReserved(virt_to_page((long long int*)(kshram[i].mem_ptr) + j));

		ClearPageReserved(virt_to_page((long long int*)(kshram[i].mem_ptr)));
		
		kshram[i].size = 0;
		kfree(kshram[i].mem_ptr);

		cdev_del(&c_dev[i]);
		destroy_dev = MKDEV(major, i);

		device_destroy(clazz, destroy_dev);
	}	


	// device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 8);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
