#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/log2.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/ktime.h>
#include <linux/smp.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/nvme_ioctl.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>

#include "zraid.h"
#include "pp.h"
#include "util.h"
#include "nvme_util.h"
#include "iosub.h"
#include "comph.h"
#include "zrwam.h"
#include "recovery.h"

// Workqueue functions
static void raizn_gc(struct work_struct *work);
static void raizn_zone_manage(struct work_struct *work);
void raizn_bg_thread(void *data);

static inline raizn_op_t raizn_op(struct bio *bio)
{
	if (bio) {
		switch (bio_op(bio)) {
		case REQ_OP_READ:
			return RAIZN_OP_READ;
		case REQ_OP_WRITE:
			return RAIZN_OP_WRITE;
		case REQ_OP_FLUSH:
			return RAIZN_OP_FLUSH;
		case REQ_OP_DISCARD:
			return RAIZN_OP_DISCARD;
		case REQ_OP_SECURE_ERASE:
			return RAIZN_OP_SECURE_ERASE;
		case REQ_OP_ZONE_OPEN:
			return RAIZN_OP_ZONE_OPEN;
		case REQ_OP_ZONE_CLOSE:
			return RAIZN_OP_ZONE_CLOSE;
		case REQ_OP_ZONE_FINISH:
			return RAIZN_OP_ZONE_FINISH;
		case REQ_OP_ZONE_APPEND:
			return RAIZN_OP_ZONE_APPEND;
		case REQ_OP_ZONE_RESET:
			return RAIZN_OP_ZONE_RESET_LOG;
		case REQ_OP_ZONE_RESET_ALL:
			return RAIZN_OP_ZONE_RESET_ALL;
		}
	}
	return RAIZN_OP_OTHER;
}


void print_buf(char *buf)
{
	int i;
	for (i = 0; i < 8; i++) {
		printk("%d", !!(((*buf) << i) & 0x80));
	}
	printk("\n");
}


void raizn_queue_gc(struct raizn_ctx *ctx, struct raizn_dev *dev)
{
	queue_work(ctx->raizn_gc_wq, &dev->gc_flush_workers.work);
	// queue_work(raizn_wq, &dev->gc_flush_workers.work);
}

void raizn_queue_manage(struct raizn_ctx *ctx, int fifo_idx)
{
#ifdef MULTI_FIFO
	queue_work(ctx->raizn_manage_wq, &ctx->zone_manage_workers[fifo_idx].work);
#else
	queue_work(ctx->raizn_manage_wq, &ctx->zone_manage_workers.work);
#endif
}

// Constructors and destructors for most data structures
static void raizn_workqueue_deinit(struct raizn_workqueue *wq)
{
	if (kfifo_initialized(&wq->work_fifo)) {
		kfifo_free(&wq->work_fifo);
	}
}

static int raizn_workqueue_init(struct raizn_ctx *ctx,
				struct raizn_workqueue *wq, int num_threads,
				void (*func)(struct work_struct *))
{
	wq->ctx = ctx;
	wq->num_threads = num_threads;
	if (kfifo_alloc(&wq->work_fifo, RAIZN_WQ_MAX_DEPTH, GFP_NOIO)) {
		return -ENOMEM;
	}
	spin_lock_init(&wq->rlock);
	spin_lock_init(&wq->wlock);
	INIT_WORK(&wq->work, func);
	return 0;
}

// caller should hold lzone->lock
static void raizn_zone_stripe_buffers_deinit(struct raizn_zone *lzone)
{
	if (lzone->stripe_buffers) {
		for (int i = 0; i < STRIPE_BUFFERS_PER_ZONE; ++i) {
			// kvfree(lzone->stripe_buffers[i].data);
			kfree(lzone->stripe_buffers[i].data);
			lzone->stripe_buffers[i].data = NULL;
		}
		// kvfree(lzone->stripe_buffers);
		kfree(lzone->stripe_buffers);
		lzone->stripe_buffers = NULL;
	}
}

static void raizn_rebuild_mgr_deinit(struct raizn_rebuild_mgr *buf)
{
	kfree(buf->open_zones);
	kfree(buf->incomplete_zones);
}

static int raizn_rebuild_mgr_init(struct raizn_ctx *ctx,
				  struct raizn_rebuild_mgr *mgr)
{
	mutex_init(&mgr->lock);
	mgr->incomplete_zones =
		kzalloc(BITS_TO_BYTES(ctx->params->num_zones), GFP_NOIO);
	mgr->open_zones =
		kzalloc(BITS_TO_BYTES(ctx->params->num_zones), GFP_NOIO);
	if (!mgr->incomplete_zones || !mgr->open_zones) {
		return -ENOMEM;
	}
	return 0;
}

static void raizn_zone_mgr_deinit(struct raizn_ctx *ctx)
{
	for (int zone_idx = 0; zone_idx < ctx->params->num_zones; ++zone_idx) {
		struct raizn_zone *zone = &ctx->zone_mgr.lzones[zone_idx];
		raizn_zone_stripe_buffers_deinit(zone);
		kfree(ctx->zone_mgr.lzones[zone_idx].persistence_bitmap);
		kfree(ctx->zone_mgr.lzones[zone_idx].stripe_prog_bitmap);
	}
	kfree(ctx->zone_mgr.lzones);
	kfree(ctx->zone_mgr.gen_counts);
	raizn_rebuild_mgr_deinit(&ctx->zone_mgr.rebuild_mgr);
}

static int raizn_zone_mgr_init(struct raizn_ctx *ctx)
{
	int ret;
	printk("[%s] ctx->params->num_zones: %d\n", __func__, ctx->params->num_zones);
	ctx->zone_mgr.lzones = kcalloc(ctx->params->num_zones,
				       sizeof(struct raizn_zone), GFP_NOIO);
	ctx->zone_mgr.gen_counts = kcalloc(
		roundup(ctx->params->num_zones, RAIZN_GEN_COUNTERS_PER_PAGE) /
			RAIZN_GEN_COUNTERS_PER_PAGE,
		PAGE_SIZE, GFP_NOIO);
	if (!ctx->zone_mgr.lzones || !ctx->zone_mgr.gen_counts) {
		return -ENOMEM;
	}
	for (int zone_num = 0; zone_num < ctx->params->num_zones; ++zone_num) {
		struct raizn_zone *zone = &ctx->zone_mgr.lzones[zone_num];
		int stripe_units_per_zone =
			ctx->params->lzone_capacity_sectors >>
			ctx->params->su_shift;
		atomic64_set(&zone->lzone_wp, ctx->params->lzone_size_sectors * zone_num);
		zone->start = atomic64_read(&zone->lzone_wp);
		zone->persist_wp = zone->start;
		zone->capacity = ctx->params->lzone_capacity_sectors;
		zone->len = ctx->params->lzone_size_sectors;
		zone->persistence_bitmap = kzalloc(
			BITS_TO_BYTES(stripe_units_per_zone), GFP_KERNEL);
		zone->stripe_prog_bitmap = kzalloc(ctx->params->stripe_prog_bitmap_size_bytes, GFP_KERNEL);
		// zone->persistence_bitmap = vzalloc(
		// 	BITS_TO_BYTES(stripe_units_per_zone));
		// zone->stripe_prog_bitmap = vzalloc(ctx->params->stripe_prog_bitmap_size_bytes);
		if (!zone->stripe_prog_bitmap) {
			printk("Failed to allocate stripe_prog_bitmap");
			return -ENOMEM;
		}
		zone->last_complete_stripe = -1;
		zone->waiting_str_num = -1;
		zone->waiting_str_num2= -1;
		zone->waiting_data_lba= -1;
		zone->waiting_pp_lba= -1;
		atomic_set(&zone->wp_entry_idx, 0);
		atomic_set(&zone->wait_count, 0);
		atomic_set(&zone->wait_count2, 0);
		atomic_set(&zone->wait_count_data, 0);
		atomic_set(&zone->wait_count_pp, 0);
    	// print_bitmap(ctx, zone);
		atomic_set(&zone->cond, BLK_ZONE_COND_EMPTY);
		mutex_init(&zone->lock);
		spin_lock_init(&zone->prog_bitmap_lock);
		spin_lock_init(&zone->last_comp_str_lock);
	}
	if ((ret = raizn_rebuild_mgr_init(ctx, &ctx->zone_mgr.rebuild_mgr))) {
		return ret;
	}
	return 0;
}

static int raizn_rebuild_next(struct raizn_ctx *ctx)
{
	struct raizn_rebuild_mgr *mgr = &ctx->zone_mgr.rebuild_mgr;
	int zoneno = -1;
	if (!bitmap_empty(mgr->open_zones, ctx->params->num_zones)) {
		zoneno =
			find_first_bit(mgr->open_zones, ctx->params->num_zones);
		clear_bit(zoneno, mgr->open_zones);
	} else if (!bitmap_empty(mgr->incomplete_zones,
				 ctx->params->num_zones)) {
		zoneno = find_first_bit(mgr->incomplete_zones,
					ctx->params->num_zones);
		clear_bit(zoneno, mgr->incomplete_zones);
	} else {
		ctx->zone_mgr.rebuild_mgr.end = ktime_get();
	}
	return zoneno;
}

static void raizn_rebuild_prepare(struct raizn_ctx *ctx, struct raizn_dev *dev)
{
	struct raizn_rebuild_mgr *rebuild_mgr = &ctx->zone_mgr.rebuild_mgr;
	if (rebuild_mgr->target_dev) { // Already a rebuild in progress
		return;
	}
	rebuild_mgr->target_dev = dev;
	for (int zoneno = 0; zoneno < ctx->params->num_zones; ++zoneno) {
		switch (atomic_read(&ctx->zone_mgr.lzones[zoneno].cond)) {
		case BLK_ZONE_COND_IMP_OPEN:
		case BLK_ZONE_COND_EXP_OPEN:
			set_bit(zoneno, rebuild_mgr->open_zones);
			break;
		case BLK_ZONE_COND_CLOSED:
		case BLK_ZONE_COND_FULL:
			set_bit(zoneno, rebuild_mgr->incomplete_zones);
			break;
		default:
			break;
		}
	}
}


int init_pzone_descriptor(struct blk_zone *zone, unsigned int idx, void *data)
{
	struct raizn_dev *dev = (struct raizn_dev *)data;
	struct raizn_zone *pzone = &dev->zones[idx];
	mutex_init(&pzone->lock);
	atomic_set(&pzone->cond, zone->cond);
	pzone->pzone_wp = zone->wp;
	pzone->start = zone->start;
	pzone->capacity = zone->capacity;
	pzone->len = zone->len;
	pzone->dev = dev;
	spin_lock_init(&pzone->pzone_wp_lock);
	return 0;
}

#ifdef SMALL_ZONE_AGGR
static void reinit_aggr_zones(struct raizn_ctx *ctx, struct raizn_dev *dev)
{
	int i;
	dev->num_zones /= GAP_ZONE_AGGR;
	dev->md_azone_wp = 0;
	dev->md_azone_idx = 0;
	for (i=0; i<dev->num_zones; i++)
	{
		struct raizn_zone *pzone = &dev->zones[i];
		pzone->phys_len = pzone->len;
		pzone->phys_capacity = pzone->capacity;
		pzone->pzone_wp *= NUM_ZONE_AGGR;
		pzone->start *= NUM_ZONE_AGGR;
		pzone->capacity *= NUM_ZONE_AGGR;
		pzone->len *= NUM_ZONE_AGGR;
	}
}
#endif

static int raizn_init_devs(struct raizn_ctx *ctx)
{
	int ret, zoneno;
	int boot_state = RAIZN_BOOT_CLEAN;
	BUG_ON(!ctx);
	for (int dev_idx = 0; dev_idx < ctx->params->array_width; ++dev_idx) {
		struct raizn_dev *dev = &ctx->devs[dev_idx];
		dev->num_zones = blkdev_nr_zones(dev->dev->bdev->bd_disk);
		dev->zones = kcalloc(dev->num_zones, sizeof(struct raizn_zone),
				     GFP_NOIO);
		if (!dev->zones) {
			pr_err("ERROR: %s dev->zones mem allocation failed!\n", __func__);
			return -ENOMEM;
		}
		blkdev_report_zones(dev->dev->bdev, 0, dev->num_zones,
				    init_pzone_descriptor, dev);
#ifdef SMALL_ZONE_AGGR
		reinit_aggr_zones(ctx, dev);
#endif
		ret = bioset_init(&dev->bioset, RAIZN_BIO_POOL_SIZE, 0,
				  BIOSET_NEED_BVECS);
		if (ret)
			return ret;
#if (defined PP_OUTPLACE)
		mutex_init(&dev->lock);
#else
		spin_lock_init(&dev->lock);
#endif
		mutex_init(&dev->bioset_lock);
		dev->zone_shift = ilog2(dev->zones[0].len);
		dev->idx = dev_idx;
		spin_lock_init(&dev->free_wlock);
		spin_lock_init(&dev->free_rlock);
		if ((ret = kfifo_alloc(&dev->free_zone_fifo,
				       RAIZN_RESERVED_ZONES, GFP_NOIO))) {
			pr_err("ERROR: %s kfifo for free zone allocation failed!\n", __func__);
			return ret;
		}
		kfifo_reset(&dev->free_zone_fifo);
		// Enqueue reserved zones
		for (zoneno = dev->num_zones - 1;
		     zoneno >= dev->num_zones - RAIZN_RESERVED_ZONES;
		     --zoneno) {
			struct raizn_zone *z = &dev->zones[zoneno];
			if (!kfifo_in_spinlocked(&dev->free_zone_fifo, &z, 1,
						 &dev->free_wlock)) {
				pr_err("ERROR: %s kfifo for free zone insert failed!\n", __func__);
				return -EINVAL;
			}
		}
		for (int mdtype = RAIZN_ZONE_MD_GENERAL;
		     mdtype < RAIZN_ZONE_NUM_MD_TYPES; ++mdtype) {
			if (!kfifo_out_spinlocked(&dev->free_zone_fifo,
						  &dev->md_zone[mdtype], 1,
						  &dev->free_rlock)) {
				return -EINVAL;
			}
			dev->md_zone[mdtype]->zone_type = mdtype;
			atomic64_set(&dev->md_zone[mdtype]->mdzone_wp, 0);
			pr_info("RAIZN writing mdtype %d to zone %llu (%llu)\n",
				mdtype,
				pba_to_pzone(ctx, dev->md_zone[mdtype]->start),
				dev->md_zone[mdtype]->start);
		}
		if (dev->md_zone[RAIZN_ZONE_MD_GENERAL]->pzone_wp !=
			dev->md_zone[RAIZN_ZONE_MD_GENERAL]->start) {
			boot_state |= RAIZN_BOOT_SB;
			pr_info("WP progress found in SB zone. dev: %d, wp: %llu\n",
				dev_idx, dev->md_zone[RAIZN_ZONE_MD_GENERAL]->pzone_wp);
		}
		raizn_workqueue_init(ctx, &dev->gc_ingest_workers,
				     ctx->num_gc_workers, raizn_gc);
		dev->gc_ingest_workers.dev = dev;
		raizn_workqueue_init(ctx, &dev->gc_flush_workers,
				     ctx->num_gc_workers, raizn_gc);
		dev->gc_flush_workers.dev = dev;
		dev->sb.params = *ctx->params; // Shallow copy is fine
		dev->sb.idx = dev->idx;
	}
	return boot_state;
}

static int raizn_init_volume(struct raizn_ctx *ctx)
{
	// Validate the logical zone capacity against the array
	int dev_idx;
	BUG_ON(!ctx);
	ctx->params->lzone_size_sectors = 1;
	// Autoset logical zone capacity if necessary
	if (ctx->params->lzone_capacity_sectors == 0) {
		sector_t zone_cap;
		ctx->params->lzone_capacity_sectors =
			ctx->devs[0].zones[0].capacity *
			ctx->params->stripe_width;
		zone_cap = ctx->devs[0].zones[0].capacity;
		ctx->params->num_zones = ctx->devs[0].num_zones;
		for (dev_idx = 0; dev_idx < ctx->params->array_width;
		     ++dev_idx) {
			struct raizn_dev *dev = &ctx->devs[dev_idx];
			if (dev->zones[0].capacity != zone_cap ||
			    dev->num_zones != ctx->params->num_zones) {
				pr_err("Automatic zone capacity only supported for homogeneous arrays.");
				return -1;
			}
		}
	} else {
		pr_err("Adjustable zone capacity is not yet supported.");
		return -1;
	}
#ifdef NON_POW_2_ZONE_SIZE
	ctx->params->lzone_size_sectors = ctx->params->lzone_capacity_sectors;
#else
	// Calculate the smallest power of two that is enough to hold the entire lzone capacity
	while (ctx->params->lzone_size_sectors <
	       ctx->params->lzone_capacity_sectors) {
		ctx->params->lzone_size_sectors *= 2;
	}
#endif
	ctx->params->lzone_shift = ilog2(ctx->params->lzone_size_sectors);
	// TODO: change for configurable zone size
	ctx->params->num_zones -= RAIZN_RESERVED_ZONES;
	return 0;
}

/* This function should be callable from any point in the code, and
	 gracefully deallocate any data structures that were allocated.
*/
static void deallocate_target(struct dm_target *ti)
{
	struct raizn_ctx *ctx = ti->private;

	if (!ctx) {
		return;
	}
	if (bioset_initialized(&ctx->bioset)) {
		bioset_exit(&ctx->bioset);
	}

	// deallocate ctx->devs
	if (ctx->devs) {
		for (int devno = 0; devno < ctx->params->array_width; ++devno) {
			struct raizn_dev *dev = &ctx->devs[devno];
			if (dev->dev) {
				dm_put_device(ti, dev->dev);
			}
			if (bioset_initialized(&dev->bioset)) {
				bioset_exit(&dev->bioset);
			}
			kvfree(dev->zones);
			if (kfifo_initialized(&dev->free_zone_fifo)) {
				kfifo_free(&dev->free_zone_fifo);
			}
			raizn_workqueue_deinit(&dev->gc_ingest_workers);
			raizn_workqueue_deinit(&dev->gc_flush_workers);
		}
		kfree(ctx->devs);
	}

	// deallocate ctx->zone_mgr
	raizn_zone_mgr_deinit(ctx);

	kfree(ctx->params);

#ifdef MULTI_FIFO
	int i;
	// for (i=0; i<ctx->num_cpus; i++) {
	for (i=0; i<min(ctx->num_cpus, ctx->num_io_workers); i++) {
		raizn_workqueue_deinit(&ctx->io_workers[i]);
	}
	kfree(ctx->io_workers);
	for (i=0; i<min(ctx->num_cpus, ctx->num_manage_workers); i++) {
		raizn_workqueue_deinit(&ctx->zone_manage_workers[i]);
	}
	kfree(ctx->zone_manage_workers);
#else
	raizn_workqueue_deinit(&ctx->io_workers);
	raizn_workqueue_deinit(&ctx->zone_manage_workers);
#endif
	// deallocate ctx
	kfree(ctx);
}

void raizn_init_stat_counter(struct raizn_ctx *ctx)
{
	memset(&ctx->subio_counters, 0, sizeof(ctx->subio_counters));
}

#ifdef RECORD_PP_AMOUNT
void raizn_init_pp_counter(struct raizn_ctx *ctx)
{
	atomic64_set(&ctx->total_write_amount, 0);
	atomic64_set(&ctx->total_write_count, 0);
	atomic64_set(&ctx->pp_volatile, 0);
	atomic64_set(&ctx->pp_permanent, 0);
	atomic64_set(&ctx->gc_migrated, 0);
	atomic64_set(&ctx->gc_count, 0);
}
#endif

int raizn_write_sb(struct raizn_ctx *ctx, struct dm_target *ti)
{
	for (int dev_idx = 0; dev_idx < ctx->params->array_width; ++dev_idx) {
		struct raizn_dev *dev = &ctx->devs[dev_idx];
		struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
		struct raizn_zone *mdzone;
		bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_FUA);
		bio_set_dev(bio, dev->dev->bdev);
		if (bio_add_page(bio, virt_to_page(&dev->sb), sizeof(dev->sb),
					0) != sizeof(dev->sb)) {
			ti->error = "Failed to write superblock";
			return -1;
		}
		mdzone = dev->md_zone[RAIZN_ZONE_MD_GENERAL];
		mdzone->pzone_wp += sizeof(dev->sb);
		bio->bi_iter.bi_sector = mdzone->start;
		// bio->bi_private = NULL;
	#ifdef SMALL_ZONE_AGGR
		if (raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1)) {
	#else
		if (raizn_submit_bio(ctx, __func__, bio, 1)) {
	#endif
			ti->error = "IO error when writing superblock";
			return -1;
		}
		bio_put(bio);
	}
	return 0;
}

int raizn_mempool_init(struct raizn_ctx *ctx)
{
	int i;
	int max_parity_num = ctx->params->max_io_len / ctx->params->stripe_sectors + 
		((ctx->params->max_io_len % ctx->params->stripe_sectors) ? 0 : 1) + 2;
	ctx->params->mempool_num = min(ctx->num_cpus, ctx->params->max_open_zones);

#if 1
	ctx->parity_buf_slab_1 = kcalloc(ctx->params->mempool_num, sizeof(struct kmem_cache *), GFP_NOIO);
	ctx->parity_buf_slab_2 = kcalloc(ctx->params->mempool_num, sizeof(struct kmem_cache *), GFP_NOIO);
	ctx->parity_buf_slab_4 = kcalloc(ctx->params->mempool_num, sizeof(struct kmem_cache *), GFP_NOIO);
	ctx->parity_buf_slab_8 = kcalloc(ctx->params->mempool_num, sizeof(struct kmem_cache *), GFP_NOIO);
	ctx->parity_buf_slab_max = kcalloc(ctx->params->mempool_num, sizeof(struct kmem_cache *), GFP_NOIO);
	ctx->parity_buf_mpool_1 = kcalloc(ctx->params->mempool_num, sizeof(mempool_t *), GFP_NOIO);
	ctx->parity_buf_mpool_2 = kcalloc(ctx->params->mempool_num, sizeof(mempool_t *), GFP_NOIO);
	ctx->parity_buf_mpool_4 = kcalloc(ctx->params->mempool_num, sizeof(mempool_t *), GFP_NOIO);
	ctx->parity_buf_mpool_8 = kcalloc(ctx->params->mempool_num, sizeof(mempool_t *), GFP_NOIO);
	ctx->parity_buf_mpool_max = kcalloc(ctx->params->mempool_num, sizeof(mempool_t *), GFP_NOIO);
	for (i=0; i<ctx->params->mempool_num; i++) {
		ctx->parity_buf_slab_1[i] = kmem_cache_create("parity_buf_slab_1", (1 * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ctx->parity_buf_slab_1[i]) {
			printk(KERN_ERR "Failed to create kmem cache\n");
			return -ENOMEM;
		}
		ctx->parity_buf_mpool_1[i] = mempool_create_slab_pool(MEMPOOL_MIN_SIZE, ctx->parity_buf_slab_1[i]);
		if (!ctx->parity_buf_mpool_1[i]) {
			kmem_cache_destroy(ctx->parity_buf_slab_1[i]);
			printk(KERN_ERR "Failed to create mempool\n");
			return -ENOMEM;
		}

		ctx->parity_buf_slab_2[i] = kmem_cache_create("parity_buf_slab_2", (2 * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ctx->parity_buf_slab_2[i]) {
			printk(KERN_ERR "Failed to create kmem cache\n");
			return -ENOMEM;
		}
		ctx->parity_buf_mpool_2[i] = mempool_create_slab_pool(MEMPOOL_MIN_SIZE/2, ctx->parity_buf_slab_2[i]);
		if (!ctx->parity_buf_mpool_2[i]) {
			kmem_cache_destroy(ctx->parity_buf_slab_2[i]);
			printk(KERN_ERR "Failed to create mempool\n");
			return -ENOMEM;
		}

		ctx->parity_buf_slab_4[i] = kmem_cache_create("parity_buf_slab_4", (4 * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ctx->parity_buf_slab_4[i]) {
			printk(KERN_ERR "Failed to create kmem cache\n");
			return -ENOMEM;
		}
		ctx->parity_buf_mpool_4[i] = mempool_create_slab_pool(MEMPOOL_MIN_SIZE/4, ctx->parity_buf_slab_4[i]);
		if (!ctx->parity_buf_mpool_4[i]) {
			kmem_cache_destroy(ctx->parity_buf_slab_4[i]);
			printk(KERN_ERR "Failed to create mempool\n");
			return -ENOMEM;
		}

		ctx->parity_buf_slab_8[i] = kmem_cache_create("parity_buf_slab_8", (8 * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ctx->parity_buf_slab_8[i]) {
			printk(KERN_ERR "Failed to create kmem cache\n");
			return -ENOMEM;
		}
		ctx->parity_buf_mpool_8[i] = mempool_create_slab_pool(MEMPOOL_MIN_SIZE/8, ctx->parity_buf_slab_8[i]);
		if (!ctx->parity_buf_mpool_8[i]) {
			kmem_cache_destroy(ctx->parity_buf_slab_8[i]);
			printk(KERN_ERR "Failed to create mempool\n");
			return -ENOMEM;
		}
		
		ctx->parity_buf_slab_max[i] = kmem_cache_create("parity_buf_slab_max", (max_parity_num * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ctx->parity_buf_slab_max[i]) {
			printk(KERN_ERR "Failed to create kmem cache\n");
			return -ENOMEM;
		}
		ctx->parity_buf_mpool_max[i] = mempool_create_slab_pool(MEMPOOL_MIN_SIZE/16, ctx->parity_buf_slab_max[i]);
		if (!ctx->parity_buf_mpool_max[i]) {
			kmem_cache_destroy(ctx->parity_buf_slab_max[i]);
			printk(KERN_ERR "Failed to create mempool\n");
			return -ENOMEM;
		}
	}
#else
	ctx->parity_buf_slab = kmem_cache_create("parity_buf_slab", (max_parity_num * ctx->params->su_sectors) << SECTOR_SHIFT, 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!ctx->parity_buf_slab) {
		printk(KERN_ERR "Failed to create kmem cache\n");
		return -ENOMEM;
	}
	ctx->parity_buf_mpool = mempool_create_slab_pool(MEMPOOL_MIN_SIZE, ctx->parity_buf_slab);
	if (!ctx->parity_buf_mpool) {
		kmem_cache_destroy(ctx->parity_buf_slab);
		printk(KERN_ERR "Failed to create mempool\n");
		return -ENOMEM;
	}
#endif

	return 0;
}


void raizn_mempool_deinit(struct raizn_ctx *ctx)
{
#if 1
	int i;
	for (i=0; i<ctx->params->mempool_num; i++) {
		mempool_destroy(ctx->parity_buf_mpool_1[i]);   
		mempool_destroy(ctx->parity_buf_mpool_2[i]);   
		mempool_destroy(ctx->parity_buf_mpool_4[i]);   
		mempool_destroy(ctx->parity_buf_mpool_8[i]);   
		mempool_destroy(ctx->parity_buf_mpool_max[i]);   
		kmem_cache_destroy(ctx->parity_buf_slab_1[i]);  
		kmem_cache_destroy(ctx->parity_buf_slab_2[i]);  
		kmem_cache_destroy(ctx->parity_buf_slab_4[i]);  
		kmem_cache_destroy(ctx->parity_buf_slab_8[i]);  
		kmem_cache_destroy(ctx->parity_buf_slab_max[i]);  
	}
	kfree(ctx->parity_buf_mpool_1);
	kfree(ctx->parity_buf_mpool_2);
	kfree(ctx->parity_buf_mpool_4);
	kfree(ctx->parity_buf_mpool_8);
	kfree(ctx->parity_buf_mpool_max);
	kfree(ctx->parity_buf_slab_1);
	kfree(ctx->parity_buf_slab_2);
	kfree(ctx->parity_buf_slab_4);
	kfree(ctx->parity_buf_slab_8);
	kfree(ctx->parity_buf_slab_max);
#else
	mempool_destroy(ctx->parity_buf_mpool);   
    kmem_cache_destroy(ctx->parity_buf_slab);   
#endif
	return;
}


int raizn_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
#ifdef SMALL_ZONE_AGGR
	printk("Small zone device. Zones are aggregated\n");
#endif

#ifdef PP_INPLACE
	printk("PP_INPLACE logging\n");
#endif
#ifdef PP_OUTPLACE
	printk("PP_OUTPLACE logging\n");
#endif
#ifdef DUMMY_HDR
	printk("Dummy header(4k) is added\n");
#endif
#ifdef PERF_MODE
	pr_warn("PERF_MODE is on. Silent bug(infinite loop) can happen!\n");
#endif

	int ret = -EINVAL;
	struct raizn_ctx *ctx;
	int idx, boot_state;
	struct gendisk *disk = dm_disk(dm_table_get_md(ti->table));

	if (argc < NUM_TABLE_PARAMS + MIN_DEVS) {
		ret = -EINVAL;
		ti->error =
			"dm-raizn: Too few arguments <stripe unit (KiB)> <num io workers> <num gc workers> <logical zone capacity in KiB (0 for auto)> [drives]";
		goto err;
	}
	ctx = kzalloc(sizeof(struct raizn_ctx), GFP_NOIO);
	if (!ctx) {
		ti->error = "dm-raizn: Failed to allocate context";
		ret = -ENOMEM;
		goto err;
	}
	ti->private = ctx;
	ctx->num_cpus = num_online_cpus();

	ctx->params = kzalloc(sizeof(struct raizn_params), GFP_NOIO);
	if (!ctx->params) {
		ti->error = "dm-raizn: Failed to allocate context params";
		ret = -ENOMEM;
		goto err;
	}
	ctx->params->array_width = argc - NUM_TABLE_PARAMS;
	ctx->params->stripe_width = ctx->params->array_width - NUM_PARITY_DEV;

#ifdef SMALL_ZONE_AGGR
	ctx->params->num_zone_aggr = NUM_ZONE_AGGR;
	ctx->params->gap_zone_aggr = GAP_ZONE_AGGR;
	ctx->params->aggr_chunk_sector = AGGR_CHUNK_SECTOR;
	ctx->params->aggr_zone_shift = ilog2(NUM_ZONE_AGGR);
	ctx->params->aggr_chunk_shift = ilog2(AGGR_CHUNK_SECTOR);
#endif

	// parse arguments
	ret = kstrtoull(argv[0], 0, &ctx->params->su_sectors);
	ctx->params->su_sectors *= 1024; // Convert from KiB to bytes
	if (ret || ctx->params->su_sectors < PAGE_SIZE ||
	    (ctx->params->su_sectors & (ctx->params->su_sectors - 1))) {
		ti->error =
			"dm-raizn: Invalid stripe unit size (must be a power of two and at least 4)";
		goto err;
	}
	ctx->params->su_sectors = ctx->params->su_sectors >>
				  SECTOR_SHIFT; // Convert from bytes to sectors
	ctx->params->stripe_sectors =
		ctx->params->su_sectors * ctx->params->stripe_width;
	ctx->params->su_shift = ilog2(ctx->params->su_sectors);
	ctx->params->stripe_shift = ilog2(ctx->params->stripe_sectors);
	ret = kstrtoint(argv[1], 0, &ctx->num_io_workers);
	if (ret) {
		ti->error = "dm-raizn: Invalid num of IO workers";
		goto err;
	}
	ctx->num_manage_workers = ctx->num_io_workers;
	// ctx->num_manage_workers = 32;
#ifdef MULTI_FIFO
	int i;
	ctx->io_workers = kcalloc(ctx->num_cpus, sizeof(struct raizn_workqueue), GFP_NOIO);
	// for (i=0; i<ctx->num_cpus; i++) {
	for (i=0; i<min(ctx->num_cpus, ctx->num_io_workers); i++) {
		raizn_workqueue_init(ctx, &ctx->io_workers[i], min(ctx->num_cpus, ctx->num_io_workers),
			     raizn_handle_io_mt);
		ctx->io_workers[i].idx = i;
	}
	ctx->zone_manage_workers = kcalloc(ctx->num_cpus, sizeof(struct raizn_workqueue), GFP_NOIO);
	for (i=0; i<min(ctx->num_cpus, ctx->num_manage_workers); i++) {
		raizn_workqueue_init(ctx, &ctx->zone_manage_workers[i], min(ctx->num_cpus, ctx->num_manage_workers),
			     raizn_zone_manage);
		ctx->zone_manage_workers[i].idx = i;
	}
#else
	raizn_workqueue_init(ctx, &ctx->io_workers, ctx->num_io_workers,
			     raizn_handle_io_mt);
	raizn_workqueue_init(ctx, &ctx->zone_manage_workers, ctx->num_manage_workers, 
				raizn_zone_manage);
#endif

	ret = kstrtoint(argv[2], 0, &ctx->num_gc_workers);
	if (ret) {
		ti->error = "dm-raizn: Invalid num of GC workers";
		goto err;
	}

	ret = kstrtoull(argv[3], 0, &ctx->params->lzone_capacity_sectors);
	ctx->params->lzone_capacity_sectors *= 1024; // Convert to bytes
	// Logical zone capacity must have an equal number of sectors per data device
	if (ret || ctx->params->lzone_capacity_sectors %
			   (ctx->params->stripe_width * SECTOR_SIZE)) {
		ti->error = "dm-raizn: Invalid logical zone capacity";
		goto err;
	}
	// Convert bytes to sectors
	ctx->params->lzone_capacity_sectors =
		ctx->params->lzone_capacity_sectors >> SECTOR_SHIFT;

	ctx->params->chunks_in_zrwa = ZRWASZ / ctx->params->su_sectors;
	ctx->params->stripes_in_stripe_prog_bitmap = ctx->params->chunks_in_zrwa * 2;
	ctx->params->stripe_prog_bitmap_size_bytes = 
		BITS_TO_BYTES(sector_to_block_addr(
			ctx->params->stripes_in_stripe_prog_bitmap * ctx->params->su_sectors * ctx->params->stripe_width));


#ifdef SAMSUNG_MODE
	ctx->params->max_io_len = (ZRWASZ * ctx->params->stripe_width / 2 - ctx->params->stripe_sectors);
#else
	ctx->params->max_io_len = (ZRWASZ * ctx->params->stripe_width / 2);
#endif
	if ((s64)ctx->params->max_io_len < 0) {
		printk("ZRWASZ is too small to setup ZRAID\n");
		goto err;
	}
	// ctx->params->max_io_len = (ZRWASZ * ctx->params->stripe_width / 4);

	// Lookup devs and set up logical volume
	ctx->devs = kcalloc(ctx->params->array_width, sizeof(struct raizn_dev),
			    GFP_NOIO);
	if (!ctx->devs) {
		ti->error = "dm-raizn: Failed to allocate devices in context";
		ret = -ENOMEM;
		goto err;
	}
	for (idx = 0; idx < ctx->params->array_width; idx++) {
		printk("dev: %s\n", argv[NUM_TABLE_PARAMS + idx]);
		ret = dm_get_device(ti, argv[NUM_TABLE_PARAMS + idx],
				    dm_table_get_mode(ti->table),
				    &ctx->devs[idx].dev);
		if (ret) {
			ti->error = "dm-raizn: Data device lookup failed";
			goto err;
		}
	}
#ifdef SAMSUNG_MODE
	// ctx->raw_bdev = blkdev_get_by_path(RAW_DEV_NAME, FMODE_READ|FMODE_WRITE|FMODE_EXCL, THIS_MODULE);
	ctx->raw_bdev = blkdev_get_by_path(RAW_DEV_NAME, FMODE_READ|FMODE_WRITE, THIS_MODULE);
	ret = PTR_ERR_OR_ZERO(ctx->raw_bdev);
	if (ret) {
		// 에러 처리
		printk("Error finding device %s\n", RAW_DEV_NAME);
		goto err;
	} else {
		// bdev 사용
	}
	ctx->params->div_capacity = get_capacity(ctx->devs[0].dev->bdev->bd_disk);
	printk("div_capacity: %llu", ctx->params->div_capacity);
#endif

// we only support recovery for ZRAID in normal mode
#if defined(PP_INPLACE) && !defined(DUMMY_HDR) && !defined(SMALL_ZONE_AGGR)
	boot_state = raizn_init_devs(ctx);
#else
	if (raizn_init_devs(ctx) != 0) {
		goto err;
	}
#endif

	bitmap_zero(ctx->dev_status, RAIZN_MAX_DEVS);
	raizn_init_volume(ctx);
	raizn_zone_mgr_init(ctx);
	raizn_init_stat_counter(ctx);
#ifdef RECORD_PP_AMOUNT
	raizn_init_pp_counter(ctx);
#endif

#if defined(PP_INPLACE) && !defined(DUMMY_HDR) && !defined(SMALL_ZONE_AGGR)
	if (boot_state != RAIZN_BOOT_CLEAN) {
		if (raizn_power_recovery(ctx, boot_state))
			goto err;
		// comph_boot_init(ctx);
	}
#endif

	bioset_init(&ctx->bioset, RAIZN_BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
	set_capacity(dm_disk(dm_table_get_md(ti->table)),
		     ctx->params->num_zones *
			     ctx->params->lzone_capacity_sectors);

#ifdef SAMSUNG_MODE
	ctx->params->max_open_zones = SAMSUNG_MAX_OPEN_ZONE / (ctx->params->array_width * ctx->params->num_zone_aggr) - RAIZN_ZONE_NUM_MD_TYPES;
	ctx->params->max_active_zones = SAMSUNG_MAX_OPEN_ZONE / (ctx->params->array_width * ctx->params->num_zone_aggr) - RAIZN_ZONE_NUM_MD_TYPES;
#else
	struct request_queue *raw_dev_queue = bdev_get_queue(ctx->devs[0].dev->bdev);
	ctx->params->max_open_zones = queue_max_open_zones(raw_dev_queue) - RAIZN_ZONE_NUM_MD_TYPES;
	ctx->params->max_active_zones = queue_max_active_zones(raw_dev_queue) - RAIZN_ZONE_NUM_MD_TYPES;
#endif
	blk_queue_max_open_zones(disk->queue, ctx->params->max_open_zones);
	blk_queue_max_active_zones(disk->queue, ctx->params->max_active_zones);


	ti->max_io_len = ZRWASZ * ctx->params->stripe_width / 2;

	ctx->raizn_wq = alloc_workqueue(WQ_NAME, WQ_UNBOUND,
				   ctx->num_io_workers +  ctx->num_gc_workers);
	ctx->raizn_gc_wq = alloc_workqueue(GC_WQ_NAME, WQ_UNBOUND, ctx->num_gc_workers);
	ctx->raizn_manage_wq = alloc_workqueue(MANAGE_WQ_NAME, WQ_HIGHPRI | WQ_UNBOUND, ctx->num_manage_workers);

	raizn_mempool_init(ctx);

#if (defined PP_INPLACE) && (defined BG_WP_SYNC)
	printk("Background WP sync thread is running..\n");
	ctx->bg_manager = kthread_run(raizn_bg_thread, ctx,
		"RAIZN_BG_MANAGER");
#endif

	if (raizn_write_sb(ctx, ti))
		goto err;

	return 0;

err:
	pr_err("raizn_ctr error: %s\n", ti->error);
	pr_err("idx: %d\n", idx);
	return ret;
}

// DM callbacks
static void raizn_dtr(struct dm_target *ti)
{	
	struct raizn_ctx *ctx = ti->private;
#if (defined PP_INPLACE) && (defined BG_WP_SYNC)
	implicit_wp_log(ctx);
#endif

#ifdef RECORD_PP_AMOUNT
	// printk("★★★---pp_volatile: %llu\n", atomic64_read(&ctx->pp_volatile));
	// printk("★★★---pp_permanent: %llu\n", atomic64_read(&ctx->pp_permanent));
	// printk("★★★---gc_migrated: %llu\n", atomic64_read(&ctx->gc_migrated));
	// printk("★★★---gc_count: %llu\n", atomic64_read(&ctx->gc_count));
#endif
#ifdef RECORD_SUBIO
	// raizn_print_subio_counter(ti->private);
#endif
#ifdef RECORD_ZFLUSH
	raizn_print_zf_counter(ti->private);
#endif

	raizn_mempool_deinit(ctx);

	if (ctx->raizn_wq) {
		destroy_workqueue(ctx->raizn_wq);
	}
	if (ctx->raizn_gc_wq) {
		destroy_workqueue(ctx->raizn_gc_wq);
	}
	if (ctx->raizn_manage_wq) {
		destroy_workqueue(ctx->raizn_manage_wq);
	}
#if (defined PP_INPLACE) && (defined BG_WP_SYNC)
	if (ctx->bg_manager) {
		kthread_stop(ctx->bg_manager);
	}
#endif
	deallocate_target(ti);
}


bool check_prog_bitmap_empty(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
    unsigned long *bitmap = lzone->stripe_prog_bitmap;
	int i;
    for(i=0; i<BITS_TO_LONGS(ctx->params->stripe_prog_bitmap_size_bytes * 8); i++)
	{
		if (*(bitmap+i) != 0) {
            return false;
        }
	}
	return true;
}

// open every pzones in the lzone associated with the given lba
// caller should hold lzone->lock
static void raizn_open_zone_zrwa(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
	// already opend by other thread
	int lzone_cond = atomic_read(&lzone->cond);
	if ((lzone_cond == BLK_ZONE_COND_IMP_OPEN) 
		|| (lzone_cond == BLK_ZONE_COND_EXP_OPEN)) {
		printk("zrwa zone already opened, lzone start: %llu\n", lzone->start);
		return;
	}

	if(!check_prog_bitmap_empty(ctx, lzone)) 
		BUG_ON(1);

	struct nvme_passthru_cmd *nvme_open_zone = kzalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);
	struct block_device *nvme_bdev;
	sector_t pba;
	int i, j, ret, zone_idx;
	zone_idx = lba_to_lzone(ctx, lzone->start);
	comph_open_zone_init(ctx, zone_idx);
#ifdef DEBUG
	BUG_ON(zone_idx >= ctx->params->num_zones);
#endif
	for (i=0; i<ctx->params->array_width; i++) {
#ifdef SAMSUNG_MODE
		nvme_bdev = ctx->raw_bdev;
		sector_t pzone_base_addr = i * ctx->params->div_capacity +
			(zone_idx * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
#else
		nvme_bdev = ctx->devs[i].dev->bdev;
		pba = ctx->devs[i].zones[zone_idx].start;
		pba = sector_to_block_addr(pba); // nvme cmd should have block unit addr
#endif

#ifdef SAMSUNG_MODE
		for (j=0; j<ctx->params->num_zone_aggr; j++) {
			pba = pzone_base_addr + j * ctx->devs[0].zones[0].phys_len;
			open_zone(nvme_open_zone, sector_to_block_addr(pba), NS_NUM, 1, 0, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
			ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_open_zone);
			if (ret != 0) {
				printk("[Failed]\tzrwa open zone: %d, idx: %d, pba: %llu\n", ret, j, (pba));
			}
#ifdef DEBUG
// #if 1
			else {
				printk("[success]\tzrwa open zone, idx: %d, pba: %llu\n", j, (pba));
			}
#endif
		}
#else
		open_zone(nvme_open_zone, pba, NS_NUM, 1, 0, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
		ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_open_zone);
		if (ret != 0) {
			printk("[Failed]\tzrwa open zone: %d, lzone start: %llu\n", ret, pba);
		}
#ifdef DEBUG
		else {
			printk("[success]\tzrwa open zone, idx: %d, lba: %llu\n", i, pba);
		}
#endif
#endif // SAMSUNG
	}
	// if (lzone_cond == BLK_ZONE_COND_EMPTY) {
	// 	for (i=0; i<ctx->params->array_width; i++) {
	// 		struct raizn_zone *pzone = &ctx->devs[i].zones[lba_to_dev_idx(ctx, lzone->start)];
	// 		pzone->pzone_wp = pzone->start;
	// 	}
	// }
	kfree(nvme_open_zone);
	atomic_set(&lzone->cond, BLK_ZONE_COND_IMP_OPEN);
}

// caller should hold lzone->lock
static int raizn_zone_stripe_buffers_init(struct raizn_ctx *ctx,
					  struct raizn_zone *lzone)
{
	if (lzone->stripe_buffers) {
		return 0;
	}
	lzone->stripe_buffers =
		kcalloc(STRIPE_BUFFERS_PER_ZONE,
			sizeof(struct raizn_stripe_buffer), GFP_NOIO);
	if (!lzone->stripe_buffers) {
		pr_err("Failed to allocate stripe buffers\n");
		return -1;
	}
	for (int i = 0; i < STRIPE_BUFFERS_PER_ZONE; ++i) {
		struct raizn_stripe_buffer *buf = &lzone->stripe_buffers[i];
		buf->data =
			// vzalloc(ctx->params->stripe_sectors << SECTOR_SHIFT);
			kzalloc(ctx->params->stripe_sectors << SECTOR_SHIFT, GFP_KERNEL);
		if (!buf->data) {
			pr_err("Failed to allocate stripe buffer data\n");
			return -1;
		}
		mutex_init(&lzone->stripe_buffers[i].lock);
	}
	return 0;
}



static int raizn_open_zone(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
	mutex_lock(&lzone->lock);
	raizn_zone_stripe_buffers_init(ctx, lzone);
#if 1
// #ifdef PP_INPLACE
	raizn_open_zone_zrwa(ctx, lzone);
#endif

	mutex_unlock(&lzone->lock);
	return 0;
}


static void raizn_request_zone_finish(struct raizn_ctx *ctx, struct raizn_zone *lzone) 
{
	if ( (atomic_read(&lzone->cond) == BLK_ZONE_COND_FULL) ) {
		printk("zrwa zone already fulled, lzone start: %llu\n", lzone->start);
		return;
	}
	struct raizn_stripe_head *fn_sh =
		raizn_stripe_head_alloc(ctx, NULL, RAIZN_OP_ZONE_FINISH);
	fn_sh->zone = lzone;

	int fifo_idx, ret;
#ifdef MULTI_FIFO
	fifo_idx = lba_to_lzone(ctx, lzone->start) %
		min(ctx->num_cpus, ctx->num_io_workers);
	ret = kfifo_in_spinlocked(
		&ctx->zone_manage_workers[fifo_idx].work_fifo, &fn_sh,
		1, &ctx->zone_manage_workers[fifo_idx].wlock);
#else
	ret = kfifo_in_spinlocked(&ctx->zone_manage_workers.work_fifo, &fn_sh, 1,
				&ctx->zone_manage_workers.wlock);
	fifo_idx = 0;
#endif
	if (!ret) {
		pr_err("ERROR: %s kfifo insert failed!\n", __func__);
		return;
	}
	raizn_queue_manage(ctx, fifo_idx);

	atomic_set(&lzone->cond, BLK_ZONE_COND_FULL);
}

// finish every pzones in the lzone associated with the given lba
static void raizn_do_finish_zone(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
	struct nvme_passthru_cmd *nvme_cmd = kzalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);
	struct block_device *nvme_bdev;
	int i, j, ret;
	for (i=0; i<ctx->params->array_width; i++) {
#ifdef SAMSUNG_MODE
		nvme_bdev = ctx->raw_bdev;
		sector_t pzone_base_addr = i * ctx->params->div_capacity +
			(lba_to_lzone(ctx, lzone->start) * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
		for (j=0; j<ctx->params->num_zone_aggr; j++) {
			blkdev_zone_mgmt(nvme_bdev,
				REQ_OP_ZONE_FINISH,
				pzone_base_addr + j * ctx->devs[0].zones[0].phys_len,
				ctx->devs[0].zones[0].phys_len,
				GFP_NOIO);
		}
#else
		nvme_bdev = ctx->devs[i].dev->bdev;
		blkdev_zone_mgmt(nvme_bdev,
			REQ_OP_ZONE_FINISH,
			ctx->devs[i].zones[lba_to_lzone(ctx, lzone->start)].start,
#ifdef NON_POW_2_ZONE_SIZE
			ctx->devs[i].zones[0].len,
#else
			1 << ctx->devs[i].zone_shift,
#endif
			GFP_NOIO);
#endif
		continue;

		sector_t dev_start_lba, flush_lba;
		dev_start_lba = ctx->devs[i].zones[lba_to_lzone(ctx, lzone->start)].start;
		dev_start_lba = sector_to_block_addr(dev_start_lba); // nvme cmd should have block unit addr
		flush_lba = dev_start_lba + ctx->devs[i].zones[lba_to_lzone(ctx, lzone->start)].capacity - 1;
		flush_lba = sector_to_block_addr(flush_lba); // nvme cmd should have block unit addr
		finish_zone(nvme_cmd, dev_start_lba, NS_NUM, 0, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
		ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_cmd);
		if (ret != 0) {
			printk("[Failed]\tzrwa finish zone: %d\n", ret);
		}
	}
	kfree(nvme_cmd);
}


static int raizn_finish_zone(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
	mutex_lock(&lzone->lock);
	raizn_zone_stripe_buffers_deinit(lzone);
#if 1
// #ifdef PP_INPLACE
	raizn_request_zone_finish(ctx, lzone);

	// struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
	// bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_FUA);
	// struct raizn_stripe_head *sh =
	// 	raizn_stripe_head_alloc(ctx, bio, RAIZN_OP_ZONE_FINISH);
	// raizn_zone_finish(sh);
	// atomic_set(&lzone->cond, BLK_ZONE_COND_FULL);
#else
	atomic_set(&lzone->cond, BLK_ZONE_COND_FULL);
#endif
	mutex_unlock(&lzone->lock);
	return 0;
}

void raizn_reset_lzone_structures(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
	lzone->last_complete_stripe = -1;
	lzone->waiting_str_num = -1;
	lzone->waiting_str_num2= -1;
	lzone->waiting_data_lba= -1;
	lzone->waiting_pp_lba= -1;
	atomic_set(&lzone->wait_count, 0);
	atomic_set(&lzone->wait_count2, 0);
	atomic_set(&lzone->wait_count_data, 0);
	atomic_set(&lzone->wait_count_pp, 0);
	raizn_reset_prog_bitmap_zone(ctx, lzone);
}

// Returns 0 on success, nonzero on failure
int raizn_zone_mgr_execute(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
#ifdef DEBUG
	BUG_ON(lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector) >= ctx->params->num_zones);
	BUG_ON(lba_to_stripe(ctx, sh->orig_bio->bi_iter.bi_sector) >= 
		(ctx->params->lzone_size_sectors / ctx->params->stripe_sectors));
#endif
	int lzone_num = lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector);
	struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lzone_num];
	int ret = 0;
	sector_t lzone_wp = 0;
	if (sh->op == RAIZN_OP_WRITE) {
		switch (atomic_read(&lzone->cond)) {
		case BLK_ZONE_COND_FULL:
		case BLK_ZONE_COND_READONLY:
		case BLK_ZONE_COND_OFFLINE:
			ret = -1; // Cannot write to a full or failed zone
			break;
		case BLK_ZONE_COND_EMPTY: // Init buffers for empty zone
			raizn_open_zone(ctx, lzone);
		case BLK_ZONE_COND_CLOSED: // Empty and closed transition to imp open
#if 1
// #ifdef PP_INPLACE
#else
			atomic_set(&lzone->cond, BLK_ZONE_COND_IMP_OPEN);
#endif
		case BLK_ZONE_COND_IMP_OPEN:
		case BLK_ZONE_COND_EXP_OPEN:
		default:
			lzone_wp = atomic64_read(&lzone->lzone_wp);
			// Empty, closed, imp and exp open all perform check to see if zone is now full
			if (sh->status == RAIZN_IO_COMPLETED) {
				atomic64_add(bio_sectors(sh->orig_bio), &lzone->lzone_wp);
				lzone_wp += bio_sectors(sh->orig_bio);
			} else if (lzone_wp >
				   sh->orig_bio->bi_iter.bi_sector) {
				pr_err("Cannot execute op %d to address %llu < wp %llu, zone addr: %p\n",
				       bio_op(sh->orig_bio),
				       sh->orig_bio->bi_iter.bi_sector,
				       lzone_wp,
					   lzone);
				return -1;
			}
			if (lzone_wp >= lzone->start + lzone->capacity) {
				raizn_finish_zone(ctx, lzone);
			}
		}
	}
	if (sh->op == RAIZN_OP_ZONE_RESET) {
		switch (atomic_read(&lzone->cond)) {
		case BLK_ZONE_COND_READONLY:
		case BLK_ZONE_COND_OFFLINE:
			ret = -1;
			break;
		case BLK_ZONE_COND_FULL:
		case BLK_ZONE_COND_IMP_OPEN:
		case BLK_ZONE_COND_EXP_OPEN:
		case BLK_ZONE_COND_EMPTY:
		case BLK_ZONE_COND_CLOSED:
		default:
			raizn_zone_stripe_buffers_deinit(lzone); // checks for null
			raizn_reset_lzone_structures(ctx, lzone);
			if (sh->status == RAIZN_IO_COMPLETED) {
				atomic_set(&lzone->cond, BLK_ZONE_COND_EMPTY);
				atomic64_set(&lzone->lzone_wp, lzone->start);
			}
		}
	}
	if (sh->op == RAIZN_OP_ZONE_CLOSE) {
		switch (atomic_read(&lzone->cond)) {
		case BLK_ZONE_COND_READONLY:
		case BLK_ZONE_COND_OFFLINE:
			ret = -1;
			break;
		case BLK_ZONE_COND_FULL:
		case BLK_ZONE_COND_IMP_OPEN:
		case BLK_ZONE_COND_EXP_OPEN:
		case BLK_ZONE_COND_EMPTY:
		case BLK_ZONE_COND_CLOSED:
		default:
			// raizn_zone_stripe_buffers_deinit(lzone); // checks for null
			if (sh->status == RAIZN_IO_COMPLETED) {
				atomic_set(&lzone->cond, BLK_ZONE_COND_CLOSED);
			}
		}
	}
	if (sh->op == RAIZN_OP_ZONE_FINISH) {
		switch (atomic_read(&lzone->cond)) {
		case BLK_ZONE_COND_READONLY:
		case BLK_ZONE_COND_OFFLINE:
			ret = -1;
			break;
		case BLK_ZONE_COND_FULL:
		case BLK_ZONE_COND_IMP_OPEN:
		case BLK_ZONE_COND_EXP_OPEN:
		case BLK_ZONE_COND_EMPTY:
		case BLK_ZONE_COND_CLOSED:
		default:
			raizn_zone_stripe_buffers_deinit(lzone); // checks for null
			raizn_reset_lzone_structures(ctx, lzone);
			if (sh->status == RAIZN_IO_COMPLETED) {
				atomic_set(&lzone->cond, BLK_ZONE_COND_FULL);
				atomic64_set(&lzone->lzone_wp, lzone->start + lzone->capacity);
			}
		}
	}


	// if (op_is_flush(sh->orig_bio->bi_opf)) {
	// 	// Update persistence bitmap, TODO: this only works for writes now
	// 	sector_t start = sh->orig_bio->bi_iter.bi_sector;
	// 	sector_t len = bio_sectors(sh->orig_bio);
	// 	int start_su = lba_to_su(ctx, start);
	// 	int end_su = lba_to_su(ctx, start + len);
	// 	if (start_su < end_su) {
	// 		// Race condition if async reset, but that is not standard
	// 		bitmap_set(lzone->persistence_bitmap, start_su,
	// 			   end_su - start_su);
	// 	}
	// }
	return ret;
}

void raizn_degraded_read_reconstruct(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	sector_t start_lba = sh->orig_bio->bi_iter.bi_sector;
	sector_t cur_lba = start_lba;
	// Iterate through clone, splitting stripe units that have to be reconstructed
	int failed_dev_idx = find_first_bit(ctx->dev_status, RAIZN_MAX_DEVS);
	while (cur_lba < bio_end_sector(sh->orig_bio)) {
		int parity_dev_idx = lba_to_parity_dev_idx(ctx, cur_lba);
		int failed_dev_su_idx = failed_dev_idx > parity_dev_idx ?
						failed_dev_idx - 1 :
						failed_dev_idx;
		sector_t cur_stripe_start_lba =
			lba_to_stripe_addr(ctx, cur_lba);
		sector_t cur_stripe_failed_su_start_lba =
			cur_stripe_start_lba +
			(failed_dev_su_idx * ctx->params->su_sectors);
		if (parity_dev_idx !=
			    failed_dev_idx // Ignore stripes where the failed device is the parity device
		    &&
		    !(cur_stripe_failed_su_start_lba + ctx->params->su_sectors <
		      start_lba) // Ignore stripes that end before the failed SU
		    &&
		    !(cur_stripe_failed_su_start_lba >
		      bio_end_sector(
			      sh->orig_bio)) // Ignore stripes that start after the failed SU
		) {
			sector_t cur_su_end_lba =
				min(bio_end_sector(sh->orig_bio),
				    cur_stripe_failed_su_start_lba +
					    ctx->params->su_sectors);
			sector_t start_offset = cur_lba - start_lba;
			sector_t len = cur_su_end_lba - cur_lba;
			struct bio *split,
				*clone = bio_clone_fast(sh->orig_bio, GFP_NOIO,
							&ctx->bioset);
			struct bio *temp =
				bio_alloc_bioset(GFP_NOIO, 1, &ctx->bioset);
			void *stripe_units[RAIZN_MAX_DEVS];
			struct raizn_sub_io *subio = sh->sub_ios[0];
			int xor_buf_idx = 0;
			sector_t added;
			BUG_ON(!clone);
			BUG_ON(!temp);
			bio_advance(clone, start_offset << SECTOR_SHIFT);
			if (len < bio_sectors(clone)) {
				split = bio_split(clone, len, GFP_NOIO,
						  &ctx->bioset);
			} else {
				split = clone;
				clone = NULL;
			}
			BUG_ON(!split);
			for (int subio_idx = 0; subio;
			     subio = sh->sub_ios[++subio_idx]) {
				if (subio->sub_io_type == RAIZN_SUBIO_REBUILD &&
				    lba_to_stripe(ctx,
						  subio->header.header.start) ==
					    lba_to_stripe(ctx, cur_lba) &&
				    subio->data) {
					stripe_units[xor_buf_idx++] =
						subio->data;
				}
			}
			if (xor_buf_idx > 1) {
				xor_blocks(xor_buf_idx, len << SECTOR_SHIFT,
					   stripe_units[0], stripe_units);
			}
			if ((added = bio_add_page(
				     temp, virt_to_page(stripe_units[0]),
				     len << SECTOR_SHIFT,
				     offset_in_page(stripe_units[0]))) !=
			    len << SECTOR_SHIFT) {
				sh->orig_bio->bi_status = BLK_STS_IOERR;
				pr_err("Added %llu bytes to temp bio, expected %llu\n",
				       added, len);
			}
			// Copy the data back
			bio_copy_data(split, temp);
			bio_put(split);
			bio_put(temp);
			if (clone) {
				bio_put(clone);
			}
		}
		cur_lba = cur_stripe_start_lba + ctx->params->stripe_sectors;
	}
}



static void raizn_rebuild_read_next_stripe(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_dev *rebuild_dev = ctx->zone_mgr.rebuild_mgr.target_dev;
	raizn_stripe_head_hold_completion(sh);
	BUG_ON(ctx->params->stripe_sectors << SECTOR_SHIFT >
	       1 << KMALLOC_SHIFT_MAX);
	// Reuse parity bufs to hold the entire data for this IO
	sh->lba = ctx->zone_mgr.rebuild_mgr.rp;
	ctx->zone_mgr.rebuild_mgr.rp += ctx->params->stripe_sectors;
	sh->parity_bufs =
		kzalloc(ctx->params->stripe_sectors << SECTOR_SHIFT, GFP_KERNEL);
	if (!sh->parity_bufs) {
		pr_err("Fatal error: failed to allocate rebuild buffer\n");
	}
	// Iterate and map each buffer to a device bio
	for (int bufno = 0; bufno < ctx->params->stripe_width; ++bufno) {
		void *bio_data =
			sh->parity_bufs +
			bufno * (ctx->params->su_sectors << SECTOR_SHIFT);
		struct raizn_dev *dev = bufno >= rebuild_dev->idx ?
						&ctx->devs[bufno + 1] :
						&ctx->devs[bufno];
		struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(
			sh, &dev->bioset, 1, RAIZN_SUBIO_REBUILD, NULL);
		bio_set_op_attrs(subio->bio, REQ_OP_READ, 0);
		bio_set_dev(subio->bio, dev->dev->bdev);
		if (bio_add_page(subio->bio, virt_to_page(bio_data),
				 ctx->params->su_sectors << SECTOR_SHIFT,
				 offset_in_page(bio_data)) !=
		    ctx->params->su_sectors << SECTOR_SHIFT) {
			pr_err("Fatal error: failed to add pages to rebuild read bio\n");
		}
		subio->bio->bi_iter.bi_sector =
			lba_to_pba_default(ctx, sh->lba);
#ifdef SMALL_ZONE_AGGR
		raizn_submit_bio_aggr(ctx, __func__, subio->bio, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif
	}
	raizn_stripe_head_release_completion(sh);
}

static void raizn_zone_manage(struct work_struct *work)
{
	struct raizn_workqueue *wq = container_of(work, struct raizn_workqueue, work);
	struct raizn_dev *dev = wq->dev;
	struct raizn_stripe_head *sh;

	while (kfifo_out_spinlocked(&wq->work_fifo, &sh, 1, &wq->rlock)) {
		if (sh->op == RAIZN_OP_ZONE_FINISH) {
			raizn_do_finish_zone(sh->ctx, sh->zone);
		}
		else if (sh->op == RAIZN_OP_ZONE_ZRWA_FLUSH) {
			zrwam_do_zrwa_flush(sh, sh->start_lba, sh->end_lba);
		}
		raizn_stripe_head_free(sh);
	}
}

// The garbage collector handles garbage collection of device zones as well as rebuilding/reshaping
static void raizn_gc(struct work_struct *work)
{
	struct raizn_workqueue *wq =
		container_of(work, struct raizn_workqueue, work);
	struct raizn_dev *dev = wq->dev;
	struct raizn_stripe_head *sh;
	int ret, j;
	unsigned int flags;
	while (kfifo_out_spinlocked(&wq->work_fifo, &sh, 1, &wq->rlock)) {
		struct raizn_ctx *ctx = sh->ctx;
		struct raizn_zone *gczone = sh->zone;
		sector_t gczone_wp = gczone->pzone_wp;

		if (sh->op == RAIZN_OP_GC && gczone_wp > gczone->start) {
			if (gczone_wp > gczone->start) {
				// profile_bio(sh);
				BUG_ON((gczone->start * dev->zones[0].len) <
				       ctx->params->num_zones);
#ifdef RECORD_PP_AMOUNT
		        atomic64_inc(&ctx->gc_count);
#endif
#ifdef SAMSUNG_MODE
				struct block_device *nvme_bdev = ctx->raw_bdev;
				sector_t pzone_base_addr = dev->idx * ctx->params->div_capacity +
					(pba_to_pzone(ctx, gczone->start) * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
				for (j=0; j<ctx->params->num_zone_aggr; j++) {
					blkdev_zone_mgmt(nvme_bdev,
						REQ_OP_ZONE_FINISH,
						pzone_base_addr + j * ctx->devs[0].zones[0].phys_len,
						ctx->devs[0].zones[0].phys_len,
						GFP_NOIO);
				}
#else
				blkdev_zone_mgmt(dev->dev->bdev,
					REQ_OP_ZONE_FINISH,
					gczone->start,
#ifdef NON_POW_2_ZONE_SIZE
					dev->zones[0].len,
#else
					1 << dev->zone_shift,
#endif
					GFP_NOIO);
#endif
				if (gczone->zone_type ==
				    RAIZN_ZONE_MD_GENERAL) {
					size_t gencount_size =
						PAGE_SIZE *
						roundup(ctx->params->num_zones,
							RAIZN_GEN_COUNTERS_PER_PAGE) /
						RAIZN_GEN_COUNTERS_PER_PAGE;
					struct raizn_sub_io *gencount_io =
						raizn_alloc_md(
							sh, 0, gczone->dev,
							RAIZN_ZONE_MD_GENERAL,
							RAIZN_SUBIO_OTHER,
							ctx->zone_mgr.gen_counts,
							gencount_size);
					struct raizn_sub_io *sb_io =
						raizn_alloc_md(
							sh, 0, gczone->dev,
							RAIZN_ZONE_MD_GENERAL,
							RAIZN_SUBIO_OTHER,
							&gczone->dev->sb,
							PAGE_SIZE);
					bio_set_op_attrs(gencount_io->bio,
							 REQ_OP_ZONE_APPEND,
							 REQ_FUA);
					bio_set_op_attrs(sb_io->bio,
							 REQ_OP_ZONE_APPEND,
							 REQ_FUA);
#ifdef PP_INPLACE					
					// TODO: add sbuf_io as below MD_PARITY_LOG. PP_INPLACE uses SB zone as PP zone.
#endif

#ifdef RECORD_PP_AMOUNT
		        	atomic64_add(gencount_size >> SECTOR_SHIFT, &ctx->pp_permanent);
		        	atomic64_add(PAGE_SIZE >> SECTOR_SHIFT, &ctx->pp_permanent);
		        	atomic64_add(gencount_size >> SECTOR_SHIFT, &ctx->gc_migrated);
		        	atomic64_add(PAGE_SIZE >> SECTOR_SHIFT, &ctx->gc_migrated);
#endif

#ifdef SMALL_ZONE_AGGR
					raizn_submit_bio_aggr(ctx, __func__, gencount_io->bio, gczone->dev, 0);
					raizn_submit_bio_aggr(ctx, __func__, sb_io->bio, gczone->dev, 0);
#else
					raizn_submit_bio(ctx, __func__, gencount_io->bio, 0);
					raizn_submit_bio(ctx, __func__, sb_io->bio, 0);
#endif
				} 
#ifdef PP_OUTPLACE
				else if (gczone->zone_type ==
					   RAIZN_ZONE_MD_PARITY_LOG) {
					raizn_stripe_head_hold_completion(sh);
					for (int zoneno = 0;
					     zoneno < ctx->params->num_zones;
					     ++zoneno) {
						struct raizn_zone *lzone =
							&ctx->zone_mgr
								 .lzones[zoneno];
						int cond;
						size_t stripe_offset_bytes;
						sector_t lzone_wp = atomic64_read(&lzone->lzone_wp);
						mutex_lock(&lzone->lock);
						cond = atomic_read(
							&lzone->cond);
						stripe_offset_bytes =
							lba_to_stripe_offset(
								ctx, lzone_wp)
							<< SECTOR_SHIFT;
						if ((cond == BLK_ZONE_COND_IMP_OPEN ||
						     cond == BLK_ZONE_COND_EXP_OPEN ||
						     cond == BLK_ZONE_COND_CLOSED) &&
						    stripe_offset_bytes) {
							struct raizn_stripe_buffer *buf =
								&lzone->stripe_buffers
									 [lba_to_stripe(
										  ctx,
										  lzone_wp) &
									  STRIPE_BUFFERS_MASK];
							void *data = kmalloc(
								stripe_offset_bytes,
								GFP_NOIO);
							struct raizn_sub_io
								*sbuf_io;
							BUG_ON(!data);
							memcpy(data, buf->data,
							       stripe_offset_bytes);
							sbuf_io = raizn_alloc_md(
								sh, 0,
								gczone->dev,
								RAIZN_ZONE_MD_PARITY_LOG,
								RAIZN_SUBIO_PP_OUTPLACE,
								data,
								stripe_offset_bytes);
							bio_set_op_attrs(
								sbuf_io->bio,
								REQ_OP_ZONE_APPEND,
								REQ_FUA);
							sbuf_io->data = data;

#ifdef RECORD_PP_AMOUNT
							atomic64_add(stripe_offset_bytes >> SECTOR_SHIFT, &ctx->pp_permanent);
							atomic64_add(stripe_offset_bytes >> SECTOR_SHIFT, &ctx->gc_migrated);
#endif

#ifdef SMALL_ZONE_AGGR
							raizn_submit_bio_aggr(ctx, __func__, sbuf_io->bio, gczone->dev, 0);
#else
							raizn_submit_bio(ctx, __func__, sbuf_io->bio, 0);
#endif			
						}
						mutex_unlock(&lzone->lock);
					}
					raizn_stripe_head_release_completion(
						sh);
				} 
#endif
				else {
					pr_err("FATAL: Cannot garbage collect zone %llu on dev %d of type %d\n",
					       gczone->start / dev->zones[0].len,
					       gczone->dev->idx,
					       gczone->zone_type);
				}
				int cnt = 0;
				while (atomic_read(&gczone->refcount) > 0) {
					if (cnt > 10000) {
						printk("## Skip waiting in GC");
						break;
					}
					cnt++;
					udelay(10);
				}
#ifdef SAMSUNG_MODE
				nvme_bdev = ctx->raw_bdev;
				pzone_base_addr = dev->idx * ctx->params->div_capacity +
					(pba_to_pzone(ctx, gczone->start) * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
				for (j=0; j<ctx->params->num_zone_aggr; j++) {
					blkdev_zone_mgmt(nvme_bdev,
						REQ_OP_ZONE_RESET,
						pzone_base_addr + j * ctx->devs[0].zones[0].phys_len,
						ctx->devs[0].zones[0].phys_len,
						GFP_NOIO);
				}
#else
				blkdev_zone_mgmt(dev->dev->bdev,
						 REQ_OP_ZONE_RESET,
						 gczone->start,
#ifdef NON_POW_2_ZONE_SIZE
						 dev->zones[0].len,
#else
						 1 << dev->zone_shift,
#endif
						 GFP_NOIO);
#endif
				gczone->pzone_wp = gczone->start;
				gczone->zone_type = RAIZN_ZONE_DATA;
				atomic_set(&gczone->cond, BLK_ZONE_COND_EMPTY);
				ret = kfifo_in_spinlocked(&dev->free_zone_fifo,
						    &gczone, 1,
						    &dev->free_wlock);
				if (!ret) {
					pr_err("ERROR: %s kfifo insert failed!\n", __func__);
					return;
				}
			}
		} else if (sh->op == RAIZN_OP_REBUILD_INGEST) {
			int next_zone;
			raizn_rebuild_prepare(ctx, dev);
			if ((next_zone = raizn_rebuild_next(ctx)) >= 0) {
				struct raizn_zone *cur_zone =
					&ctx->zone_mgr.lzones[next_zone];
				ctx->zone_mgr.rebuild_mgr.rp =
					next_zone *
					ctx->params->lzone_size_sectors;
				atomic64_set(&ctx->zone_mgr.rebuild_mgr.wp, 
					lba_to_pba_default(
						ctx,
						ctx->zone_mgr.rebuild_mgr.rp));

				while (ctx->zone_mgr.rebuild_mgr.rp <
				       	cur_zone->pzone_wp) {
					struct raizn_stripe_head *next_stripe =
						raizn_stripe_head_alloc(
							ctx, NULL,
							RAIZN_OP_REBUILD_INGEST);
					raizn_rebuild_read_next_stripe(
						next_stripe);
				}
			}
			raizn_stripe_head_free(sh);
		} else if (sh->op == RAIZN_OP_REBUILD_FLUSH) {
			struct raizn_zone *zone =
				&dev->zones[lba_to_lzone(ctx, sh->lba)];
			struct raizn_sub_io *subio =
				raizn_stripe_head_alloc_bio(
					sh, &dev->bioset, 1,
					RAIZN_SUBIO_REBUILD, NULL);
			void *stripe_units[RAIZN_MAX_DEVS];
			char *dst;
			for (int i = 0; i < ctx->params->stripe_width; ++i) {
				stripe_units[i] = sh->parity_bufs +
						  i * (ctx->params->su_sectors
						       << SECTOR_SHIFT);
			}
			dst = stripe_units[0];
			BUG_ON(!dst);
			// XOR data
			xor_blocks(ctx->params->stripe_width,
				   ctx->params->su_sectors << SECTOR_SHIFT, dst,
				   stripe_units);
			// Submit write
			bio_set_op_attrs(subio->bio, REQ_OP_WRITE, REQ_FUA);
			bio_set_dev(subio->bio, dev->dev->bdev);
			if (bio_add_page(subio->bio, virt_to_page(dst),
					 ctx->params->su_sectors
						 << SECTOR_SHIFT,
					 offset_in_page(dst)) !=
			    ctx->params->su_sectors << SECTOR_SHIFT) {
				pr_err("Fatal error: failed to add pages to rebuild write bio\n");
			}
			subio->bio->bi_iter.bi_sector = zone->pzone_wp;
#ifdef SMALL_ZONE_AGGR
			raizn_submit_bio_aggr(ctx, __func__, subio->bio, dev, 0);
#else			
			raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif			
			// Update write pointer
			spin_lock_irqsave(&zone->pzone_wp_lock, flags);
			zone->pzone_wp += ctx->params->su_sectors;
			spin_unlock_irqrestore(&zone->pzone_wp_lock, flags);
		}
	}
}

void implicit_wp_log(struct raizn_ctx *ctx)
{
	int zoneno, i;
	for (zoneno=0; zoneno<ctx->params->num_zones; zoneno++) {
		struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
		int lzone_cond = atomic_read(&lzone->cond);

		// do only for active zones
		if (!(lzone_cond == BLK_ZONE_COND_IMP_OPEN) || (lzone_cond == BLK_ZONE_COND_CLOSED))
			continue;

		sector_t lzone_wp = atomic64_read(&lzone->lzone_wp);
		if (lzone_wp != lzone->persist_wp) {
			struct raizn_stripe_head *sh = raizn_stripe_head_alloc(
				ctx, NULL, RAIZN_OP_WP_LOG);
			for (i=0; i<2; i++)
            	raizn_stripe_head_alloc_subio(sh, RAIZN_SUBIO_WP_LOG); // need to allocate subio for two wp_logs

			raizn_write_wp_log(sh, lzone_wp);
			lzone->persist_wp = lzone_wp;
		}
	}
}

void raizn_bg_thread(void *data)
{
	struct raizn_ctx *ctx = data;
	u64 last_wtime_store = -1;

	set_freezable();
	do {
		msleep(BG_MANAGER_WAKEUP);

		if (ctx->last_write_time == last_wtime_store)
			continue;

		u64 now = ktime_get_ns();
		if (ctx->last_write_time > now) {
			BUG_ON(0);
		}

		if (now - ctx->last_write_time > WRITE_IDLE_THRESHOLD * 1000 * 1000) {
			implicit_wp_log(ctx);
		}

	} while (!kthread_should_stop());
}

int raizn_process_stripe_head(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	int ret;
	switch (sh->op) {
	case RAIZN_OP_READ:
		return raizn_read(sh);
	case RAIZN_OP_WRITE:
		ctx->last_write_time = ktime_get_ns();

		// Validate the write can be serviced
		if (raizn_zone_mgr_execute(sh) != 0) {
			pr_err("Failed to validate write\n");
			return DM_MAPIO_KILL;
		}
		if (ctx->num_io_workers > 1) {
#ifdef MULTI_FIFO
			int fifo_idx;
			// fifo_idx = (lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector) + lba_to_stripe(ctx, sh->orig_bio->bi_iter.bi_sector)) %
			fifo_idx = (lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector)) %
				min(ctx->num_cpus, ctx->num_io_workers);

			ret = kfifo_in_spinlocked(&ctx->io_workers[fifo_idx].work_fifo, &sh, 1,
					    &ctx->io_workers[fifo_idx].wlock);
			if (!ret) {
				pr_err("ERROR: %s kfifo insert failed!\n", __func__);
				BUG_ON(1);
			}
			queue_work(ctx->raizn_wq, &ctx->io_workers[fifo_idx].work);
#else
			// Push it onto the fifo
			ret = kfifo_in_spinlocked(&ctx->io_workers.work_fifo, &sh, 1,
					    &ctx->io_workers.wlock);
			if (!ret) {
				pr_err("ERROR: %s kfifo insert failed!\n", __func__);
				BUG_ON(1);
			}
			queue_work(ctx->raizn_wq, &ctx->io_workers.work);
#endif
			return DM_MAPIO_SUBMITTED;
		} else {
			return raizn_write(sh);
		}
	case RAIZN_OP_FLUSH:
		return raizn_flush(sh);
	case RAIZN_OP_DISCARD:
		pr_err("RAIZN_OP_DISCARD is not supported.\n");
		return DM_MAPIO_KILL;
	case RAIZN_OP_SECURE_ERASE:
		pr_err("RAIZN_OP_SECURE_ERASE is not supported.\n");
		return DM_MAPIO_KILL;
	case RAIZN_OP_WRITE_ZEROES:
		pr_err("RAIZN_OP_WRITE_ZEROES is not supported.\n");
		return DM_MAPIO_KILL;
	case RAIZN_OP_ZONE_OPEN:
		return raizn_zone_open(sh);
	case RAIZN_OP_ZONE_CLOSE:
		return raizn_zone_close(sh);
	case RAIZN_OP_ZONE_FINISH:
		return raizn_zone_finish(sh);
	case RAIZN_OP_ZONE_APPEND:
		return raizn_zone_append(sh);
	case RAIZN_OP_ZONE_RESET_LOG:
		return raizn_zone_reset_top(sh);
	case RAIZN_OP_ZONE_RESET:
		return raizn_zone_reset_bottom(sh);
	case RAIZN_OP_ZONE_RESET_ALL:
		return raizn_zone_reset_all(sh);
	default:
		pr_err("This stripe unit should not be handled by process_stripe_head\n");
		return DM_MAPIO_KILL;
	}
	return DM_MAPIO_KILL;
}

static int raizn_map(struct dm_target *ti, struct bio *bio)
{
	struct raizn_ctx *ctx = (struct raizn_ctx *)ti->private;
	struct raizn_stripe_head *sh =
		raizn_stripe_head_alloc(ctx, bio, raizn_op(bio));

	return raizn_process_stripe_head(sh);
}

static void raizn_status(struct dm_target *ti, status_type_t type,
			 unsigned int status_flags, char *result,
			 unsigned int maxlen)
{
	struct raizn_ctx *ctx = ti->private;
	if (ctx->zone_mgr.rebuild_mgr.end) {
		pr_info("Rebuild took %llu ns\n",
			ktime_to_ns(
				ktime_sub(ctx->zone_mgr.rebuild_mgr.end,
					  ctx->zone_mgr.rebuild_mgr.start)));
	}
#ifdef PROFILING
	pr_info("write sectors = %llu\n",
		atomic64_read(&ctx->counters.write_sectors));
	pr_info("read sectors = %llu\n",
		atomic64_read(&ctx->counters.read_sectors));
	pr_info("writes = %d\n", atomic_read(&ctx->counters.writes));
	pr_info("reads = %d\n", atomic_read(&ctx->counters.reads));
	pr_info("zone_resets = %d\n", atomic_read(&ctx->counters.zone_resets));
	pr_info("flushes = %d\n", atomic_read(&ctx->counters.flushes));
	pr_info("preflush = %d\n", atomic_read(&ctx->counters.preflush));
	pr_info("fua = %d\n", atomic_read(&ctx->counters.fua));
	pr_info("gc_count = %d\n", atomic_read(&ctx->counters.gc_count));
#endif
}

static int raizn_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct raizn_ctx *ctx = ti->private;
	int i, ret = 0;
	if (!ctx || !ctx->devs) {
		return -1;
	}

	for (i = 0; i < ctx->params->array_width; i++) {
		struct raizn_dev *dev = &ctx->devs[i];
		ret = fn(ti, dev->dev, 0, dev->num_zones * dev->zones[0].len,
			 data);
		if (ret) {
			break;
		}
	}
	struct gendisk *disk = dm_disk(dm_table_get_md(ti->table));
	blk_queue_max_hw_sectors(disk->queue, ctx->params->max_io_len);
	dm_set_target_max_io_len(ti, ctx->params->max_io_len);

#ifdef WRITE_BACK_CACHE
	blk_queue_write_cache(disk->queue, true, true);
#endif

	// Why does dm keep trying to add more sectors to the device???
	set_capacity(dm_disk(dm_table_get_md(ti->table)),
		     ctx->params->num_zones * ctx->params->lzone_size_sectors);
	return ret;
}

static void raizn_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct raizn_ctx *ctx = (struct raizn_ctx *)ti->private;
	limits->chunk_sectors = ctx->params->lzone_size_sectors;
	blk_limits_io_min(limits, ctx->params->su_sectors << SECTOR_SHIFT);
	blk_limits_io_opt(limits, ctx->params->stripe_sectors << SECTOR_SHIFT);
	limits->zoned = BLK_ZONED_HM;
}

static void raizn_suspend(struct dm_target *ti)
{
}

static void raizn_resume(struct dm_target *ti)
{
}

static int raizn_report_zones(struct dm_target *ti,
			      struct dm_report_zones_args *args,
			      unsigned int nr_zones)
{
	struct raizn_ctx *ctx = ti->private;
#ifdef NON_POW_2_ZONE_SIZE
	int zoneno = args->next_sector / ctx->params->lzone_size_sectors;
#else
	int zoneno = args->next_sector >> ctx->params->lzone_shift;
#endif
	struct raizn_zone *zone = &ctx->zone_mgr.lzones[zoneno];
	struct blk_zone report;

	if (!nr_zones || zoneno > ctx->params->num_zones) {
		return args->zone_idx;
	}
	mutex_lock(&zone->lock);
	report.start = zone->start;
	report.len = ctx->params->lzone_size_sectors;
	report.wp = atomic64_read(&zone->lzone_wp);
	report.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	report.cond = (__u8)atomic_read(&zone->cond);
	report.non_seq = 0;
	report.reset = 0;
	report.capacity = ctx->params->lzone_capacity_sectors;
	mutex_unlock(&zone->lock);
	args->start = report.start;
	args->next_sector += ctx->params->lzone_size_sectors;
	return args->orig_cb(&report, args->zone_idx++, args->orig_data);
}

// More investigation is necessary to see what this function is actually used for in f2fs etc.
static int raizn_prepare_ioctl(struct dm_target *ti, struct block_device **bdev)
{
	struct raizn_ctx *ctx = ti->private;
	*bdev = ctx->devs[0].dev->bdev;
	return 0;
}

static int raizn_command(struct raizn_ctx *ctx, int argc, char **argv,
			 char *result, unsigned maxlen)
{
	static const char errmsg[] = "Error: Invalid command\n";
	printk("[raizn_command] argc: %d, %d %d %d\n", 
		argc,
		strcmp(argv[0], RAIZN_DEV_TOGGLE_CMD),
		strcmp(argv[0], RAIZN_DEV_REBUILD_CMD),
		strcmp(argv[0], RAIZN_DEV_STAT_CMD)
		);
	if (argc >= 2 && !strcmp(argv[0], RAIZN_DEV_TOGGLE_CMD)) {
		int dev_idx, ret;
		static const char successmsg[] =
			"Success: Set device %d to %s\n";
		ret = kstrtoint(argv[1], 0, &dev_idx);
		if (!ret && dev_idx < ctx->params->array_width) {
			bool old_status =
				test_and_change_bit(dev_idx, ctx->dev_status);
			if (strlen("DISABLED") + strlen(successmsg) < maxlen) {
				sprintf(result, successmsg, dev_idx,
					old_status ? "ACTIVE" : "DISABLED");
			}
		}
	} else if (argc >= 2 && !strcmp(argv[0], RAIZN_DEV_REBUILD_CMD)) {
		int dev_idx, ret, j;
		static const char successmsg[] =
			"Success: Resetting and rebuilding device %d\n";
		ret = kstrtoint(argv[1], 0, &dev_idx);
		if (!ret && strlen(successmsg) < maxlen) {
			struct raizn_dev *dev = &ctx->devs[dev_idx];
			struct raizn_stripe_head *sh = raizn_stripe_head_alloc(
				ctx, NULL, RAIZN_OP_REBUILD_INGEST);
			set_bit(dev_idx, ctx->dev_status);
			sprintf(result, successmsg, dev_idx);
			// 1. Reset all zones
			for (int zoneno = 0; zoneno < dev->num_zones;
			     ++zoneno) {
#ifdef SAMSUNG_MODE
				struct block_device *nvme_bdev = ctx->raw_bdev;
				sector_t pzone_base_addr = dev_idx * ctx->params->div_capacity +
				 	(zoneno * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
				for (j=0; j<ctx->params->num_zone_aggr; j++) {
					blkdev_zone_mgmt(nvme_bdev,
						REQ_OP_ZONE_RESET,
						pzone_base_addr + j * ctx->devs[0].zones[0].phys_len,
						ctx->devs[0].zones[0].phys_len,
						GFP_NOIO);
				}
#else
				blkdev_zone_mgmt(dev->dev->bdev,
						 REQ_OP_ZONE_RESET,
#ifdef NON_POW_2_ZONE_SIZE
						 zoneno * dev->zones[0].len,
						 dev->zones[0].len,
#else
						zoneno << dev->zone_shift,
						1 << dev->zone_shift,
#endif
						 GFP_NOIO);
#endif
			}
			// 2. Reset all physical zone descriptors for this device
			blkdev_report_zones(dev->dev->bdev, 0, dev->num_zones,
					    init_pzone_descriptor, dev);
			// 3. Schedule rebuild
			ctx->zone_mgr.rebuild_mgr.start = ktime_get();
			ret = kfifo_in_spinlocked(&dev->gc_ingest_workers.work_fifo,
					    &sh, 1,
					    &dev->gc_ingest_workers.wlock);
			if (!ret) {
				pr_err("ERROR: %s kfifo insert failed!\n", __func__);
				return -1;
			}
			queue_work(ctx->raizn_gc_wq, &dev->gc_ingest_workers.work);
			// queue_work(raizn_wq, &dev->gc_ingest_workers.work);
		}
	}
	else if (argc == 1 && !strcmp(argv[0], RAIZN_DEV_STAT_CMD)) {
#ifdef RECORD_PP_AMOUNT
		printk("★★★---total_write_count: %llu\n", atomic64_read(&ctx->total_write_count));
		printk("★★★---total_write_amount: %llu(KB)\n", atomic64_read(&ctx->total_write_amount)/2);
		printk("★★★---pp_volatile: %llu(KB)\n", atomic64_read(&ctx->pp_volatile)/2);
		printk("★★★---pp_permanent: %llu(KB)\n", atomic64_read(&ctx->pp_permanent)/2);
		printk("★★★---gc_count: %llu\n", atomic64_read(&ctx->gc_count));
		printk("★★★---gc_migrated: %llu(KB)\n", atomic64_read(&ctx->gc_migrated)/2);
#endif
	}
	else if (argc == 1 && !strcmp(argv[0], RAIZN_DEV_STAT_RESET_CMD)) {
#ifdef RECORD_PP_AMOUNT
		printk("★★★---dev_stat reset\n");
		raizn_init_pp_counter(ctx);
#endif
	}
	else if (strlen(errmsg) < maxlen) {
		strcpy(result, errmsg);
	}
	return 1;
}

#ifdef RAIZN_TEST
void raizn_test_parse_command(int argc, char **argv)
{
	// Command structure
	// <function_name> [args...]
	if (!strcmp(argv[0], "lba_to_stripe")) {
	} else if (!strcmp(argv[0], "lba_to_su")) {
	} else if (!strcmp(argv[0], "lba_to_lzone")) {
	} else if (!strcmp(argv[0], "lba_to_parity_dev_idx")) {
	} else if (!strcmp(argv[0], "lba_to_parity_dev")) {
	} else if (!strcmp(argv[0], "lba_to_dev")) {
	} else if (!strcmp(argv[0], "lba_to_lzone_offset")) {
	} else if (!strcmp(argv[0], "lba_to_stripe_offset")) {
	} else if (!strcmp(argv[0], "bytes_to_stripe_offset")) {
	} else if (!strcmp(argv[0], "lba_to_stripe_addr")) {
	} else if (!strcmp(argv[0], "lba_to_pba_default")) {
	} else if (!strcmp(argv[0], "validate_parity")) {
	}
}

static int raizn_message(struct dm_target *ti, unsigned argc, char **argv,
			 char *result, unsigned maxlen)
{
	struct raizn_ctx *ctx = ti->private;
	int idx;
	pr_info("Received message, output buffer maxlen=%d\n", maxlen);
	for (idx = 0; idx < argc; ++idx) {
		pr_info("argv[%d] = %s\n", idx, argv[idx]);
	}
	raizn_command(ctx, argc, argv, result, maxlen);
	return 1;
}
#else
static int raizn_message(struct dm_target *ti, unsigned argc, char **argv,
			 char *result, unsigned maxlen)
{
	return raizn_command(ctx, argc, argv, result, maxlen);
}
#endif

// Module
static struct target_type raizn = {
	.name = "zraid",
	.version = { 1, 0, 0 },
	.module = THIS_MODULE,
	.ctr = raizn_ctr,
	.dtr = raizn_dtr,
	.map = raizn_map,
	.io_hints = raizn_io_hints,
	.status = raizn_status,
	.prepare_ioctl = raizn_prepare_ioctl,
	.report_zones = raizn_report_zones,
	.postsuspend = raizn_suspend,
	.resume = raizn_resume,
	.features = DM_TARGET_ZONED_HM,
	.iterate_devices = raizn_iterate_devices,
	.message = raizn_message,
};

static int init_raizn(void)
{
	return dm_register_target(&raizn);
}

static void cleanup_raizn(void)
{
	dm_unregister_target(&raizn);
}
module_init(init_raizn);
module_exit(cleanup_raizn);
MODULE_LICENSE("GPL");
