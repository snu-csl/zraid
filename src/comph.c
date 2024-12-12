#include "zraid.h"
#include "pp.h"
#include "util.h"
#include "nvme_util.h"


static void raizn_rebuild_endio(struct bio *bio)
{
	struct raizn_sub_io *subio = bio->bi_private;
	struct raizn_stripe_head *sh = subio->sh;
	sector_t lba = sh->lba;
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_dev *dev = ctx->zone_mgr.rebuild_mgr.target_dev;
	bio_put(bio);
	if (atomic_dec_and_test(&sh->refcount)) {
		if (sh->op == RAIZN_OP_REBUILD_INGEST) {
			// Queue a flush
			sh->op = RAIZN_OP_REBUILD_FLUSH;
			kfifo_in_spinlocked(
				&dev->gc_flush_workers.work_fifo, &sh, 1,
				&dev->gc_flush_workers.wlock);
			queue_work(ctx->raizn_gc_wq, &dev->gc_flush_workers.work);
		} else {
			struct raizn_zone *lzone =
				&ctx->zone_mgr.lzones[lba_to_lzone(ctx, lba)];
			raizn_stripe_head_free(sh);
			if (lba + ctx->params->stripe_sectors >= atomic64_read(&lzone->lzone_wp)) {
				sh = raizn_stripe_head_alloc(
					ctx, NULL, RAIZN_OP_REBUILD_INGEST);
				kfifo_in_spinlocked(
					&dev->gc_ingest_workers.work_fifo,
					&sh, 1,
					&dev->gc_ingest_workers.wlock);
				queue_work(ctx->raizn_gc_wq,
					   &dev->gc_ingest_workers.work);
			}
		}
	}
}


int raizn_assign_wp_log_bio(struct raizn_stripe_head *sh, struct raizn_sub_io *wlio, int dev_idx, sector_t dev_lba)
{
	struct page *p;
	struct bio *wlbio = wlio->bio;
#ifdef DEBUG
	BUG_ON(!wlbio);
#endif
    p = is_vmalloc_addr(&wlio->header) ? vmalloc_to_page(&wlio->header) :
                        virt_to_page(&wlio->header);
	if (bio_add_page(wlbio, p, PAGE_SIZE, offset_in_page(&wlio->header)) !=
	    PAGE_SIZE) {
		pr_err("Failed to add dummy header page\n");
		bio_endio(wlbio);
		return NULL;
	}
	wlbio->bi_iter.bi_sector = dev_lba;
    wlio->dev = &sh->ctx->devs[dev_idx];
    wlio->zone = &sh->ctx->devs[dev_idx].zones[pba_to_pzone(sh->ctx, dev_lba)];
    if (sh->orig_bio)
        wlbio->bi_opf = sh->orig_bio->bi_opf | REQ_FUA;
    else
        wlbio->bi_opf = REQ_OP_WRITE;
	bio_set_dev(wlbio, sh->ctx->devs[dev_idx].dev->bdev);

	return 1;
}

inline void raizn_alloc_wp_log(struct raizn_stripe_head *sh, struct raizn_dev *dev, struct raizn_sub_io *wlio)
{
	raizn_stripe_head_alloc_bio(
		sh, &dev->bioset, 1, RAIZN_SUBIO_WP_LOG, wlio);
}

sector_t get_wp_pba(struct raizn_ctx *ctx, sector_t end_lba, int pp_distance, int wp_entry_idx)
{
    sector_t dev_pba, pzone_start;
    pzone_start = ctx->devs[0].zones[lba_to_lzone(ctx, end_lba)].start;
    dev_pba = pzone_start + ((lba_to_stripe(ctx, end_lba - 1) + pp_distance) << ctx->params->su_shift);
    dev_pba += wp_entry_idx * PAGE_SIZE / SECTOR_SIZE;

    return dev_pba;
}

void generate_wp_log(struct raizn_stripe_head *sh, struct raizn_sub_io *wlio, sector_t end_lba)
{
    wlio->header.wp_log_entry.magic = WP_LOG_ENTRY_MAGIC;
    wlio->header.wp_log_entry.timestamp = ktime_get_ns(); 
    wlio->header.wp_log_entry.lba = end_lba; 
}

static void __raizn_write_wp_log(struct raizn_stripe_head *sh, sector_t end_lba, int wp_entry_idx)
{
    int pp_distance;
    struct raizn_ctx *ctx = sh->ctx;
    sector_t dev_pba;
    get_pp_distance(ctx, end_lba, &pp_distance);
    if (pp_distance >= 0) {
        struct raizn_sub_io *wlio1, *wlio2;
        int parity_dev_idx, wl_dev_idx;
        dev_pba = get_wp_pba(ctx, end_lba, pp_distance, wp_entry_idx);
        parity_dev_idx = lba_to_parity_dev_idx(ctx, end_lba - 1);
        wl_dev_idx = (parity_dev_idx + 1) % ctx->params->array_width; // next to parity dev (sequnece = 0)
    
        wlio1 = sh->sub_ios[0];
		raizn_alloc_wp_log(sh, &ctx->devs[parity_dev_idx], wlio1);
        generate_wp_log(sh, wlio1, end_lba);
        if (!raizn_assign_wp_log_bio(sh, wlio1, parity_dev_idx, dev_pba)) {
			pr_err("Fatal: Failed to assign pp bio\n");
			BUG_ON(1);
		}
        wlio2 = sh->sub_ios[1];
		raizn_alloc_wp_log(sh, &ctx->devs[wl_dev_idx], wlio2);
		// wlio2 = raizn_alloc_wp_log(sh, &ctx->devs[wl_dev_idx]);
        generate_wp_log(sh, wlio2, end_lba);
        if (!raizn_assign_wp_log_bio(sh, wlio2, wl_dev_idx, dev_pba)) {
			pr_err("Fatal: Failed to assign pp bio\n");
			BUG_ON(1);
		}
#ifdef SMALL_ZONE_AGGR
        raizn_submit_bio_aggr(ctx, __func__, wlio1->bio, &ctx->devs[parity_dev_idx], 0);
        raizn_submit_bio_aggr(ctx, __func__, wlio2->bio, &ctx->devs[wl_dev_idx], 0);
#else
        raizn_submit_bio(ctx, __func__, wlio1->bio, 0);
        raizn_submit_bio(ctx, __func__, wlio2->bio, 0);
#endif
    }
    else // WP log to separated zone
        raizn_write_md(
			sh,
			lba_to_lzone(ctx, end_lba),
			lba_to_parity_dev(ctx, end_lba),
			RAIZN_ZONE_MD_GENERAL,
            RAIZN_SUBIO_WP_LOG,
			sh->sub_ios[0], 
            0);
}

// sh must have at least 2 pre-allocated sub_ios 
int raizn_write_wp_log(struct raizn_stripe_head *sh, sector_t end_lba)
{
    struct raizn_ctx *ctx = sh->ctx;
    int wp_entry_idx;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, end_lba)];
    if ((s32)lba_to_stripe(ctx, end_lba) <= (s32)READ_ONCE(lzone->last_complete_stripe)) {
        printk("[raizn_write_wp_log] Skipped. zone: %d, end_stripe: %d, last_complete_stripe: %d",
            lba_to_lzone(ctx, end_lba), lba_to_stripe(ctx, end_lba), READ_ONCE(lzone->last_complete_stripe));
        return 0;
    }

    sh->op = RAIZN_OP_WP_LOG;
    wp_entry_idx = atomic_inc_return(&lzone->wp_entry_idx) % (ctx->params->su_sectors / (PAGE_SIZE / SECTOR_SIZE));
    __raizn_write_wp_log(sh, end_lba, wp_entry_idx);
    return 1;
}


void raizn_update_prog_bitmap(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba)
{
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, start_lba)];
    char bit_pattern[64];
    volatile unsigned long *bitmap = lzone->stripe_prog_bitmap;
    int bit_loc = 0, total_bits = sector_to_block_addr(end_lba - start_lba);
    int start_stripe_num = lba_to_stripe(ctx, start_lba);
    int start_stripe_idx = start_stripe_num % ctx->params->stripes_in_stripe_prog_bitmap;
    sector_t start_stripe_offset = lba_to_stripe_offset(ctx, start_lba);
    int end_stripe_num = lba_to_stripe(ctx, end_lba-1);
    int i=0, j;
    int stripe_num = start_stripe_idx;
    int bit = 0;

    if ((start_stripe_num/ctx->params->stripes_in_stripe_prog_bitmap) == 
            (end_stripe_num/ctx->params->stripes_in_stripe_prog_bitmap))
        bitmap_set(bitmap, start_stripe_idx * sector_to_block_addr(ctx->params->stripe_sectors) +
            sector_to_block_addr(start_stripe_offset), 
            total_bits);
    else {
        unsigned long bits_to_bitmap_end = 
            (ctx->params->stripes_in_stripe_prog_bitmap - start_stripe_idx) * sector_to_block_addr(ctx->params->stripe_sectors)
             - sector_to_block_addr(start_stripe_offset);
        // bitmap start to end stripe
        bitmap_set(bitmap, 0, 
            total_bits - bits_to_bitmap_end);
        // start stripe to bitmap end
        bitmap_set(bitmap, start_stripe_idx * sector_to_block_addr(ctx->params->stripe_sectors) +
            sector_to_block_addr(start_stripe_offset), bits_to_bitmap_end);
    }
}

// wait until given stripe becomes durable. bitmap is checked from the start of the stripe to the end_offset
inline bool check_stripe_complete(struct raizn_ctx *ctx, struct raizn_zone *lzone, int stripe_num)
{
    int i;
    char bit_pattern[64];
    unsigned long content = 0;
    volatile unsigned long *bitmap = (unsigned long *)lzone->stripe_prog_bitmap;
    unsigned long mask = ULONG_MAX;
    int stripe_idx = stripe_num % ctx->params->stripes_in_stripe_prog_bitmap;

    for(i=0; i<BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)); i++)
    {
        content = READ_ONCE(*(bitmap + stripe_idx * BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + i));
        if ((content & mask) != mask) {
            return false;
        }
    }
    return true;
}

// wait all previous requests are persisted.
inline int check_stripe_complete_range(struct raizn_ctx *ctx, struct raizn_zone *lzone, sector_t start_stripe_num, sector_t end_stripe_num)
{
    int stripe_num;
    for (stripe_num=start_stripe_num; stripe_num<=end_stripe_num; stripe_num++) { 
        if (!check_stripe_complete(ctx, lzone, stripe_num)) {
            if (stripe_num == start_stripe_num)
                return -1;
            else
                return stripe_num - 1;
        }
    }
    return end_stripe_num;
}


// reset only one stripe
inline void raizn_reset_prog_bitmap_stripe(struct raizn_ctx *ctx, struct raizn_zone *lzone, unsigned int stripe_num)
{
    unsigned int stripe_idx = stripe_num % ctx->params->stripes_in_stripe_prog_bitmap; // important! we allocated memory for only ZRWA area
    char *bitmap = (char *) lzone->stripe_prog_bitmap;
	memset(bitmap + BITS_TO_BYTES(stripe_idx * sector_to_block_addr(ctx->params->stripe_sectors)), 0,
        BITS_TO_BYTES(sector_to_block_addr(ctx->params->stripe_sectors)));
} 

// reset the whole zone
inline void raizn_reset_prog_bitmap_zone(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
    char *bitmap = (char *) lzone->stripe_prog_bitmap;
	memset(bitmap, 0, ctx->params->stripe_prog_bitmap_size_bytes);
}

void raizn_update_complete_stripe(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba)
{
    int stripe_num, new_comp_str_num, prev_comp_str_num, end_stripe_num = lba_to_stripe(ctx, end_lba - 1);
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, start_lba)];

    prev_comp_str_num = lzone->last_complete_stripe;
    if (prev_comp_str_num >= end_stripe_num) {
        return;
    }
    new_comp_str_num = check_stripe_complete_range(ctx, lzone, 
       prev_comp_str_num + 1, end_stripe_num + ctx->params->chunks_in_zrwa); 
       // Reason why check further than end_stripe: request completion can be reordered
    if (new_comp_str_num > READ_ONCE(lzone->last_complete_stripe)) {
        WRITE_ONCE(lzone->last_complete_stripe, new_comp_str_num);
        for (stripe_num=prev_comp_str_num + 1; stripe_num<=new_comp_str_num; stripe_num++) {
            raizn_reset_prog_bitmap_stripe(ctx, lzone, stripe_num);
        }
    }
}

// flush_lba is on lzone's address space. zrwa flush handler will convert this lba to pba & dev_idx.
void raizn_request_zrwa_flush(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba)
{
	int fifo_idx, ret;
    struct raizn_stripe_head *sh =
		raizn_stripe_head_alloc(ctx, NULL, RAIZN_OP_ZONE_ZRWA_FLUSH);
    sh->start_lba = start_lba;
    sh->end_lba = end_lba;
    sh->zf_submit_time = ktime_get_ns();
    sh->zf_submitted = true;

	fifo_idx = (lba_to_lzone(ctx, end_lba)) %
	    	min(ctx->num_cpus, ctx->num_manage_workers);
	ret = kfifo_in_spinlocked(
		&ctx->zone_manage_workers[fifo_idx].work_fifo, &sh,
		1, &ctx->zone_manage_workers[fifo_idx].wlock);
    if (!ret) {
		pr_err("ERROR: %s kfifo insert failed!\n", __func__);
		return;
	}
	raizn_queue_manage(ctx, fifo_idx);
}

void raizn_pp_manage(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba)
{
    unsigned long flags;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, start_lba)];

    if (lba_to_su(ctx, end_lba) != lba_to_su(ctx, start_lba)) {
        raizn_request_zrwa_flush(ctx, start_lba, end_lba);
    }
    spin_lock_irqsave(&lzone->prog_bitmap_lock, flags);
    raizn_update_prog_bitmap(ctx, start_lba, end_lba);
    raizn_update_complete_stripe(ctx, start_lba, end_lba);
    spin_unlock_irqrestore(&lzone->prog_bitmap_lock, flags);
}

void comph_endio(struct bio *bio)
{
	struct raizn_sub_io *subio = bio->bi_private;
	struct raizn_stripe_head *sh = subio->sh;
	bool defer_put = subio->defer_put;

	if (bio->bi_status != BLK_STS_OK) {
		if (subio->zone) {
			sector_t zoneno;
			if (subio->zone->zone_type == RAIZN_ZONE_DATA) {
				zoneno = lba_to_lzone(sh->ctx,
						      subio->zone->start);
			} else {
#ifdef NON_POW_2_ZONE_SIZE
				zoneno = subio->zone->start /
					 subio->zone->dev->zones[0].len;
#else
				zoneno = subio->zone->start >>
					 subio->zone->dev->zone_shift;
#endif
			}
		}
	}
	// for GC zone cleaning
	if (subio->sub_io_type == RAIZN_SUBIO_PP_OUTPLACE) {
		atomic_dec(&subio->zone->refcount);
	}
	if (sh->op == RAIZN_OP_REBUILD_INGEST ||
	    sh->op == RAIZN_OP_REBUILD_FLUSH) {
		raizn_rebuild_endio(bio);
	} else {
		if (!defer_put) {
			bio_put(bio);
		}
		if (atomic_dec_and_test(&sh->refcount)) {
			bool bio_extended = 0; // for FLUSH
			sh->status = RAIZN_IO_COMPLETED;
			if (sh->op == RAIZN_OP_WRITE ||
			    sh->op == RAIZN_OP_ZONE_RESET ||
			    sh->op == RAIZN_OP_ZONE_CLOSE ||
			    sh->op == RAIZN_OP_ZONE_FINISH ||
			    sh->op == RAIZN_OP_FLUSH) {
				raizn_zone_mgr_execute(sh);
			} else if (sh->op == RAIZN_OP_DEGRADED_READ) {
				raizn_degraded_read_reconstruct(sh);
			}
			if (sh->orig_bio) {
				sector_t start_lba = sh->orig_bio->bi_iter.bi_sector;
				sector_t end_lba = bio_end_sector(sh->orig_bio);

#if (defined PP_OUTPLACE)
				bio_endio(sh->orig_bio);
#else
				if ((sh->op == RAIZN_OP_WP_LOG) || // WP_LOG complete
					((sh->op != RAIZN_OP_FLUSH) && !op_is_flush(sh->orig_bio->bi_opf))) {// Normal read/write
					bio_endio(sh->orig_bio);
				}
				else { // flush-related I/Os, must write WP LOG
					if (raizn_write_wp_log(sh, end_lba)) // sh->op changed to RAIZN_OP_WP_LOG in raizn_write_wp_log()
					{
						bio_extended = 1;
					}
					else
						bio_endio(sh->orig_bio);
				}
				
#endif

#if (defined PP_OUTPLACE)
				if (sh->op == RAIZN_OP_WRITE)
#else
				if ((sh->op == RAIZN_OP_WRITE) ||
					((sh->op == RAIZN_OP_WP_LOG) && bio_extended))
#endif
				{
					// no need for MD zones		
					if (lba_to_lzone(sh->ctx, start_lba) < sh->ctx->params->num_zones) {
						raizn_pp_manage(sh->ctx, start_lba, end_lba);
					}
				}
			}
			if (!bio_extended) {
				if (sh->next) {
					raizn_process_stripe_head(sh->next);
				}
				raizn_stripe_head_free(sh);
			}
		}
	}
}

int comph_open_zone_init(struct raizn_ctx *ctx, int zoneno)
{
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
    sector_t stripe_start_lba = lba_to_stripe_addr(ctx, atomic64_read(&lzone->lzone_wp));

    WRITE_ONCE(lzone->last_complete_stripe, lba_to_stripe(ctx, atomic64_read(&lzone->lzone_wp)) - 1);

    if (stripe_start_lba != lzone->start)
        raizn_update_prog_bitmap(ctx, stripe_start_lba, atomic64_read(&lzone->lzone_wp));
}
