#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>

#include <linux/sched.h>
#include <linux/dcache.h>
#include <asm/fcntl.h>
#include <asm/processor.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/gpio.h>
#include <linux/sched/rt.h>
#include <uapi/linux/sched/types.h>
#include <linux/pid.h> 
#include <linux/delay.h>
#include <linux/mm.h>

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/compiler.h>

#include <linux/pagemap.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <asm/tlbflush.h>
#include <linux/mm_types.h>
#include <linux/mmzone.h>
#include <linux/rmap.h>
#include <linux/swapops.h>

#define MY_DEV_NAME "my_dev"


#define TEST_PROC_DIR              "page_test"
#define TEST_PROC_NAME             "pid"

extern void try_to_unmap_flush(void);
extern void try_to_unmap_flush_dirty(void);
extern void update_lru_sizes(struct lruvec *lruvec,enum lru_list lru, unsigned long *nr_zone_taken);
extern int page_evictable(struct page *page);
extern int pageout_sync(struct page *page, struct address_space *mapping);
extern void putback_lru_page(struct page *page);
extern void lru_add_drain(void);
extern void put_swap_page(struct page *page, swp_entry_t entry);
extern int page_referenced(struct page *page,int is_locked,struct mem_cgroup *memcg,unsigned long *vm_flags);
extern void __delete_from_swap_cache(struct page *page);
extern void free_unref_page(struct page *page);
extern int add_to_swap(struct page *page);


/*-------------------------------------------------------------------------*/

struct proc_dir_entry *test_proc_dir = NULL;
static int pid = -1;

static int test_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "echo pid to start.now:");
    
    if(0 == pid)
    {
        seq_printf(m, "off\n");
    }else
    {
        seq_printf(m, "%d\n", pid);
    }
    
    return 0; //!! must be 0, or will show nothing T.T
}

static ssize_t test_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos)
{
    char *tmp = kzalloc((count + 1), GFP_KERNEL);
    if(!tmp){
        return -ENOMEM;
    }
    
    memset(tmp, 0x00, count+1);
    if(copy_from_user(tmp, buffer, count))
    {
        kfree(tmp);
        return -EFAULT;
    }
    
    sscanf(tmp, "%d", &pid);
 
    kfree(tmp);
    return count;
}

static int test_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, test_proc_show, NULL);
}

static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = test_proc_open,
    .read = seq_read,
    .write = test_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static int init_test_proc(void)
{
    struct proc_dir_entry *file = NULL;
    
    test_proc_dir = proc_mkdir(TEST_PROC_DIR, NULL);
    if(NULL == test_proc_dir){
        pr_err("%s Create %s failed\n", __func__, TEST_PROC_DIR);
        return -EINVAL;
    }

    file = proc_create(TEST_PROC_NAME, 666, test_proc_dir,  &proc_fops);
    if(!file){
        pr_err("%s Create %s failed\n", __func__, TEST_PROC_NAME);
        return -EINVAL;
    }

    return 0;
}

static void proc_test_exit(void)
{
    proc_remove(test_proc_dir);
}


/*-------------------------------------------------------------------------*/


static int test_open(struct inode *inode, struct file *file)
{
    int major = MAJOR(inode->i_rdev);
    int minor = MINOR(inode->i_rdev);

    pr_info("%s: major=%d, minor=%d\n", __func__, major, minor);
    return 0;
}

static int test_release(struct inode *inode, struct file *file)
{
    pr_info("%s \n", __func__);

    return 0;
}

static ssize_t test_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
    pr_info("%s \n", __func__);
    return 0;
}

static ssize_t test_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
    pr_info("%s \n", __func__);
    return 0;

}

static const struct file_operations test_fops = {
    .owner = THIS_MODULE,
    .open = test_open,
    .release = test_release,
    .read = test_read,
    .write = test_write
};

static struct miscdevice test_misc_device ={

    .minor = MISC_DYNAMIC_MINOR,
    .name = MY_DEV_NAME,
    .fops = &test_fops,
};

//putback没有经过严格验证，可能存在问题
static int putback_anon_page(struct pglist_data *pgdat, 
    struct lruvec *lruvec,enum lru_list lru,struct list_head *page_list)
{
    unsigned int move = 0;
    LIST_HEAD(pages_to_free);

    spin_lock(&pgdat->lru_lock);
    /*
     * Put back any unfreeable pages.
     */
    while (!list_empty(page_list)) {
        struct page *page = lru_to_page(page_list);
        VM_BUG_ON_PAGE(PageLRU(page), page);
        list_del(&page->lru);
        if (unlikely(!page_evictable(page))) {
            spin_unlock(&pgdat->lru_lock);
            putback_lru_page(page);
            spin_lock(&pgdat->lru_lock);
            continue;
        }

        SetPageLRU(page);
        add_page_to_lru_list(page, lruvec, lru);
        move ++;

        if (put_page_testzero(page)) {
            __ClearPageLRU(page);
            __ClearPageActive(page);
            //里边调用了__mod_lruvec_state、mem_cgroup_update_lru_size函数，导致“undefined!”
            //del_page_from_lru_list(page, lruvec, lru);
            del_page_from_lru_list(page, lruvec, lru);

            if (unlikely(PageCompound(page))) {
                spin_unlock(&pgdat->lru_lock);
                mem_cgroup_uncharge(page);
                (*get_compound_page_dtor(page))(page);
                spin_lock(&pgdat->lru_lock);
            } else
                list_add(&page->lru, &pages_to_free);
        }
    }
    spin_unlock(&pgdat->lru_lock);
    /*
     * To save our caller's stack, now use input list for pages to free.
     */
    list_splice(&pages_to_free, page_list);
    return move;
}

//参考内核 shrink_page_list 修改
static int shrink_anon_page(    struct list_head *page_list, struct page *page)
{
    int ret = -1;
    struct address_space *mapping;
    unsigned long flags;
    enum {
        /* failed to write page out, page is locked */
        PAGE_KEEP,
        /* move page to the active list, page is locked */
        PAGE_ACTIVATE,
        /* page has been sent to the disk successfully, page is unlocked */
        PAGE_SUCCESS,
        /* page is clean and locked */
        PAGE_CLEAN,
    };

    trylock_page(page);
    if (PageAnon(page) && PageSwapBacked(page)) {
        if (!PageSwapCache(page)) {
            if (PageTransHuge(page)) {
                /* cannot split THP, skip it */
                if (!can_split_huge_page(page, NULL)){
                    goto keep_locked;
                }
                /*
                 * Split pages without a PMD map right
                 * away. Chances are some or all of the
                 * tail pages can be freed without IO.
                 */
                if (!compound_mapcount(page) &&
                    split_huge_page_to_list(page,
                                page_list)){
                    goto keep_locked;
                }
            }
            
            if (!add_to_swap(page)) {
                if (!PageTransHuge(page)){
                    goto keep_locked;
                }
                /* Fallback to swap normal pages */
                if (split_huge_page_to_list(page,
                                page_list)){
                    goto keep_locked;
                }
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
                count_vm_event(THP_SWPOUT_FALLBACK);
#endif
                if (!add_to_swap(page)){
                    goto keep_locked;
                }
            }
            /* Adding to swap updated mapping */
            mapping = page_mapping(page);
        }
    } else if (unlikely(PageTransHuge(page))) {
        /* Split file THP */
        if (split_huge_page_to_list(page, page_list))
            goto keep_locked;
    }

    if (page_mapped(page)) {
        enum ttu_flags flags = TTU_IGNORE_ACCESS | TTU_BATCH_FLUSH;

        if (unlikely(PageTransHuge(page)))
            flags |= TTU_SPLIT_HUGE_PMD;
        if (!try_to_unmap(page, flags)){
            goto keep_locked;
        }
    }

    if (PageDirty(page)) {
        try_to_unmap_flush_dirty();
        
        //pageout_sync相较于pageout，更改了回写控制参数并去掉sc
        /*
        //同步回写1页
        struct writeback_control wbc = {
            .sync_mode = WB_SYNC_ALL,
            .nr_to_write = 1,
            //.range_start = 0,
            //.range_end = LLONG_MAX,
            //.for_reclaim = 1,
            .for_sync = 1,
        };
        */
        //switch (pageout(page, mapping, NULL)) {
        switch (pageout_sync(page, mapping)) {
        case PAGE_KEEP:
            goto keep_locked;
        case PAGE_ACTIVATE:
            goto keep_locked;
        case PAGE_SUCCESS:
            if (!trylock_page(page)){
                goto keep_locked;
            }

            //实际设置为同步回写后page还是处于回写状态，所以在此处等待回写完成
            wait_on_page_writeback(page);

            if (PageDirty(page) || PageWriteback(page)){
                goto keep_locked;
            }
                
            mapping = page_mapping(page);
        case PAGE_CLEAN:
            ; /* try to free the page below */
        }
    }
    
    /*
     * 实际测试中发现当已交换出去的页被换入，再次释放时，页面的
     * PG_swapbacked和PG_swapcache标志同时被置位，且页面非脏（可能是预读操作导致的？）
     * 最终结果就是上面分支都未走，导致mapping没被赋值为非法地址
     */
    if(mapping != page_mapping(page))
    {
        //重新换入到内存的页（非脏页）？
        mapping = page_mapping(page);
    }
    
    xa_lock_irqsave(&mapping->i_pages, flags);

    //清除_refcount：到这一步时，page的_refcount应该为2
    if (!page_ref_freeze(page, 2)){
        xa_unlock_irqrestore(&mapping->i_pages, flags);
        goto keep_locked;
    }

    //释放swap交互缓存
    if (PageSwapCache(page)) {
        swp_entry_t swap = { .val = page_private(page) };
        mem_cgroup_swapout(page, swap);
        __delete_from_swap_cache(page);
        xa_unlock_irqrestore(&mapping->i_pages, flags);
        put_swap_page(page, swap);
    }
    ret = 0;
    __ClearPageLocked(page);
keep_locked:
    unlock_page(page);

    //释放页面到伙伴系统
    if(!ret){
        mem_cgroup_uncharge(page);
        try_to_unmap_flush();
        free_unref_page(page);
    }
    
    return ret;
}

static int anon_page_isolate(struct list_head *dst,
        pg_data_t *pgdat, struct lruvec *lruvec, 
        enum lru_list lru, struct page *page)
{
    int ret = -EINVAL;
    unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
    unsigned long nr_pages;
    
    spin_lock_irq(&pgdat->lru_lock);
    
    //page ref计数加1，防止page被释放
    if (likely(get_page_unless_zero(page))) {
        //page不在LRU链表，无需隔离，返回ok
        if (!PageLRU(page)){
            ret = 0;
        }else{
            //清除page lru标志
            ClearPageLRU(page);
            ret = 0;
        }
    }else{
        printk("get_page fail\n");
        ret = -EINVAL;
    }

    switch(ret)
    {
        case 0:
            nr_pages = hpage_nr_pages(page);
            nr_zone_taken[page_zonenum(page)] += nr_pages;
            
            //清除page active标志
            if(PageActive(page))
                ClearPageActive(page);
                
            //page保存在临时链表dst
            list_move(&page->lru, dst);
            break;
        default:
            break;
    }
    update_lru_sizes(lruvec, lru, nr_zone_taken);
    spin_unlock_irq(&pgdat->lru_lock);
    
    return ret;
}

int free_anon_page(struct page *page)
{
    struct zone *zone = NULL;
    pg_data_t *pgdat = NULL;
    struct lruvec *lruvec = NULL;
    enum lru_list lru;
    unsigned long vm_flags;
    int ret = -1;
    
    LIST_HEAD(page_free_list);

    zone = page_zone(page);
    pgdat = zone->zone_pgdat;
    lruvec = mem_cgroup_lruvec(pgdat, page_memcg(page));
    lru = page_lru_base_type(page);

    ret = anon_page_isolate(&page_free_list, pgdat, lruvec, lru, page);
    if(ret)
    {
        printk("isolate fail\n");
        return ret;
    }

    //清除pte 访问位，页面回收时需要清除
    page_referenced(page, 0, page_memcg(page), &vm_flags);

    ret = shrink_anon_page(&page_free_list, page);
    //页面回收失败，放回lru链表
    if(ret){
        ret = putback_anon_page(pgdat, lruvec, lru, &page_free_list);
    }

    return ret;
}

struct task_struct *get_task_by_pid(pid_t pid) {
    struct pid *proc_pid;
    struct task_struct *task;
 
    // 获取PID对象
    proc_pid = find_get_pid(pid);
    if (!proc_pid)
        return NULL;
 
    // 通过PID对象获取进程描述符
    task = pid_task(proc_pid, PIDTYPE_PID);
    if (!task) {
        put_pid(proc_pid);
        return NULL;
    }
 
    // 如果不需要再使用proc_pid，则释放它
    put_pid(proc_pid);
 
    // 返回进程描述符
    return task;
}

unsigned long virt2pfn(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn;
    unsigned long phys;
    struct page *page;
    
    // 获取PGD（页全局目录）
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        // PGD条目不存在或无效
        return 0;
    }

    // 获取PUD（页上级目录）
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        // PUD条目不存在或无效
        return 0;
    }

    // 获取PMD（页中间目录）
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || !pmd_present(*pmd)) {
        // PMD条目不存在或无效，或者页面不在内存中
        return 0;
    }

    // 使用pte_offset获取PTE（页表条目）
    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte_present(*pte)) {
        // PTE条目不存在或无效
        return 0;
    }
    
    if (!(page = pte_page(*pte))){
        return 0;
    }
    phys = page_to_phys(page);
    
    // 现在可以安全地访问PTE了
    // 例如，获取页面帧号（PFN）
    pfn = pte_pfn(*pte);
    
    if(PageMappingFlags(page))
    {
        //bit0为1,匿名映射
        free_anon_page(page);
    }
    else
    {
        //bit0为0,文件缓存
        ;
    }
    
    return pfn;
}

static struct task_struct  *thread_task;
static int pid_thread(void *arg)
{

    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma = 0;
    unsigned long vpage;    
    unsigned long pfn = 0;
    
    while(pid == -1)
    {
        msleep(1000);
    }
    
    task = get_task_by_pid(pid); // 获取当前任务组长指针
    if (!task) {
        printk("Failed to find the process.\n");
        return -1;
    }
    
    mm = task->mm; // 获取进程的内存管理信息
    if (!mm || !mm->pgd) {
        printk("Invalid memory management information or page global directory is not initialized.\n");
        return -1;
    }
    
    lru_add_drain();
    if (mm && mm->mmap){
        for (vma = mm->mmap; vma; vma = vma->vm_next){
            //只扫描堆内存，malloc的内存就在这个区域
            if (vma->vm_start <= mm->brk &&
                vma->vm_end >= mm->start_brk) {
                
                for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE){
                    pfn = virt2pfn(mm, vpage);
                }
            }
        }
    }
    
    return 0;

}


static int __init test_init(void)
{
    int ret;

    pr_info("test_init\n");

    ret = misc_register(&test_misc_device);
    if (ret != 0 ) {
        pr_err("failed to misc_register");
        return ret;
    }
    thread_task = kthread_create(pid_thread, NULL, "pid-thread");
    wake_up_process(thread_task);
    init_test_proc();
    pr_err("Minor number = %d\n", test_misc_device.minor);

    return 0;
}

static void __exit test_exit(void)
{
    pr_info("test_exit\n");
    misc_deregister(&test_misc_device);
    proc_test_exit();
}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
