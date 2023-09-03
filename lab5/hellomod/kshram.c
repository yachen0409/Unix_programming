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
#include <linux/mm.h>

#include "kshram.h"

#define MAX_DEV_NUM 8
static dev_t devnum;
static struct cdev c_dev[MAX_DEV_NUM];
static struct class *clazz;
struct buf_info{
    int size;
    void* buf;
};
static struct buf_info arr[MAX_DEV_NUM];
//static int hellomod_dev_open(struct inode *i, struct file *f) {
	//printk(KERN_INFO "hellomod: device opened.\n");
	//return 0;
//}

//static int hellomod_dev_close(struct inode *i, struct file *f) {
	//printk(KERN_INFO "hellomod: device closed.\n");
	//return 0;
//}

//static ssize_t hellomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	//printk(KERN_INFO "hellomod: read %zu bytes @ %llu.\n", len, *off);
	//return len;
//}

//static ssize_t hellomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	//printk(KERN_INFO "hellomod: write %zu bytes @ %llu.\n", len, *off);
	//return len;
//}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vmptr) {
	int dev_index;
    char *dev_name = fp->f_path.dentry->d_iname;
	//void *tmp_buf = kzalloc(4096, GFP_KERNEL);
    struct page *tmp_page;
    unsigned long page_num;

    //printk(KERN_INFO "Get dev name: %s\n", fp->f_path.dentry->d_iname);
    sscanf(dev_name, "kshram%d", &dev_index);
    printk(KERN_INFO "kshram/mmap: idx %d size %d\n", dev_index,(int)(vmptr->vm_end - vmptr->vm_start));
    //printk(KERN_INFO "Get dev index: %d\n", dev_index);
    tmp_page = virt_to_page(arr[dev_index].buf);
    page_num = page_to_pfn(tmp_page);
    if(remap_pfn_range(vmptr, vmptr->vm_start, page_num, vmptr->vm_end - vmptr->vm_start, vmptr->vm_page_prot))
        return -EAGAIN;
    return 0;
}


static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	char *dev_name = fp->f_path.dentry->d_iname;
    printk(KERN_INFO "kshram/ioctl: cmd %u arg %lu\n", cmd, arg);
    //printk(KERN_INFO "Get dev name: %s\n", fp->f_path.dentry->d_iname);
	if (cmd == KSHRAM_GETSLOTS){
        return 8;
    }
    else if(cmd == KSHRAM_GETSIZE){
        int dev_index;
        sscanf(dev_name, "kshram%d", &dev_index);
        //printk(KERN_INFO "Get dev index: %d\n", dev_index);
        return arr[dev_index].size;
    }
    else if(cmd == KSHRAM_SETSIZE){
        int dev_index;
        sscanf(dev_name, "kshram%d", &dev_index);
        //printk(KERN_INFO "Get dev index: %d\n", dev_index);
        //kfree(arr[dev_index].buf);
        //arr[dev_index].size = 0;
        arr[dev_index].buf = krealloc(arr[dev_index].buf, arg, GFP_KERNEL);
        arr[dev_index].size = (int)arg;
        return arg;
    }
    return 0;
}

static const struct file_operations hellomod_dev_fops = {
	.owner = THIS_MODULE,
	//.open = hellomod_dev_open,
    //.read = hellomod_dev_read,
	//.write = hellomod_dev_write,
    .mmap = kshram_dev_mmap,
	.unlocked_ioctl = kshram_dev_ioctl,
	//.release = hellomod_dev_close
};

static int hellomod_proc_read(struct seq_file *m, void *v) {
	//char buf[] = "`hello, world!` in /proc.\n";
	//seq_printf(m, buf);
    //seq_printf(m, "%ld, %ld\n", sizeof(*arr[0]), sizeof(arr[0]));
    for(int i = 0; i < MAX_DEV_NUM; ++i){
        seq_printf(m, "%02d: %04d\n", i, arr[i].size);
    }
	return 0;
}

static int hellomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, hellomod_proc_read, NULL);
}

static const struct proc_ops hellomod_proc_fops = {
	.proc_open = hellomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *hellomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init hellomod_init(void)
{

    int major;
    // create char dev
	if(alloc_chrdev_region(&devnum, 0, MAX_DEV_NUM, "updev") < 0)
		return -1;
	if((clazz = class_create(THIS_MODULE, "upclass")) == NULL)
		goto release_region;
	clazz->devnode = hellomod_devnode;
    //printk(KERN_INFO "IM HERE!\n");
    major = MAJOR(devnum);
    for (int i = 0; i < MAX_DEV_NUM; i++){
        //printk(KERN_INFO "i=%d", i);
        devnum = MKDEV(major, i);
        if(device_create(clazz, NULL, devnum, NULL, "kshram%d", i) == NULL)
		    goto release_class;
	    cdev_init(&c_dev[i], &hellomod_dev_fops);
	    if(cdev_add(&c_dev[i], devnum, 1) == -1)
		    goto release_device;
    }
    //arr=kzalloc(MAX_DEV_NUM*sizeof(void *), GFP_KERNEL);
    for (int i = 0; i < MAX_DEV_NUM; ++i){
        // arr = kmalloc_array(MAX_DEV_NUM, 4096, GFP_KERNEL);
        arr[i].size = 4096;
        arr[i].buf = kzalloc(4096, GFP_KERNEL);
        printk(KERN_INFO "kshram%d: %d bytes allocated @ %llx\n", i, arr[i].size, (long long)arr[i].buf);
    }
	// create proc
	proc_create("kshram", 0, NULL, &hellomod_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
    printk(KERN_INFO "Failed cdev_init!\n");
	device_destroy(clazz, devnum);
release_class:
    printk(KERN_INFO "Failed device_create!\n");
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit hellomod_cleanup(void)
{
	int major = MAJOR(devnum);
    for(int i = 0; i < MAX_DEV_NUM; ++i){
        kfree(arr[i].buf);
        arr[i].size=0;
    }
    remove_proc_entry("kshram", NULL);
    for (int i = 0; i < MAX_DEV_NUM; ++i){
	    cdev_del(&c_dev[i]);
	    device_destroy(clazz, MKDEV(major, i));
    }
	class_destroy(clazz);
	unregister_chrdev_region(devnum, MAX_DEV_NUM);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(hellomod_init);
module_exit(hellomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
