#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tty.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

//Macro SYSCALL_DEFINEn n=No of argument accepted by the system call
SYSCALL_DEFINE1(demo_print_call, const char __user *, msg)
{
    char kernel_msg[256];
    struct tty_struct *tty = NULL;
    struct file *file;
    long copied;

    if (!access_ok(msg, sizeof(kernel_msg)))
        return -EFAULT;

    copied = strncpy_from_user(kernel_msg, msg, sizeof(kernel_msg));
    
    if (copied < 0 || copied == sizeof(kernel_msg))
        return -EFAULT;

    rcu_read_lock();
    file = current->files->fdt->fd[0];  // 0 represents stdin
    if (file && file->f_op && file->f_op->read) {
        tty = file->private_data;
    }
    rcu_read_unlock();

    if (tty && tty->driver && tty->driver->ops && tty->driver->ops->write) {
        (void)tty->driver->ops->write(tty, kernel_msg, copied);
         printk(KERN_INFO "successfully printed proj_sys_call: %s\n", kernel_msg);
    } else {
        printk(KERN_INFO "proj_sys_call: %s\n", kernel_msg);
    }
    
    return copied;
}
