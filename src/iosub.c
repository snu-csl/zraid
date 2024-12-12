#include <linux/delay.h>

#include "zraid.h"
#include "pp.h"
#include "util.h"
#include "nvme_util.h"
#include "comph.h"

// Must only be called if the entire bio is handled by the read_simple path
// *Must* be called if the stripe head is of type RAIZN_OP_READ
// Bypasses the normal endio handling using bio_chain
static inline int raizn_read_simple(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct bio *split,
		*clone = bio_clone_fast(sh->orig_bio, GFP_NOIO, &ctx->bioset);
	atomic_set(&sh->refcount, 1);
	clone->bi_private = &sh->sentinel;
	clone->bi_end_io = comph_endio;
	while (round_up(clone->bi_iter.bi_sector + 1, ctx->params->su_sectors) <
	       bio_end_sector(sh->orig_bio)) {
		sector_t su_boundary = round_up(clone->bi_iter.bi_sector + 1,
						ctx->params->su_sectors);
		sector_t chunk_size = su_boundary - clone->bi_iter.bi_sector;
		struct raizn_dev *dev =
			lba_to_dev(ctx, clone->bi_iter.bi_sector);
		split = bio_split(clone, chunk_size, GFP_NOIO, &dev->bioset);
		bio_set_dev(split, dev->dev->bdev);
		split->bi_iter.bi_sector =
			lba_to_pba_default(ctx, split->bi_iter.bi_sector);
		bio_chain(split, clone);
// #if 0
#ifdef SMALL_ZONE_AGGR
		raizn_submit_bio_aggr(ctx, __func__, split, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, split, 0);
#endif
	}
#ifdef SMALL_ZONE_AGGR
	struct raizn_dev *dev =
		lba_to_dev(ctx, clone->bi_iter.bi_sector);
#endif
	bio_set_dev(clone,
		lba_to_dev(ctx, clone->bi_iter.bi_sector)->dev->bdev);
	clone->bi_iter.bi_sector =
		lba_to_pba_default(ctx, clone->bi_iter.bi_sector);
#ifdef SMALL_ZONE_AGGR
	raizn_submit_bio_aggr(ctx, __func__, clone, dev, 0);
#else
	raizn_submit_bio(ctx, __func__, clone, 0);
#endif
	return DM_MAPIO_SUBMITTED;
}

int raizn_read(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	sector_t start_lba = sh->orig_bio->bi_iter.bi_sector;
	// Determine if the read involves rebuilding a missing stripe unit

	struct bio *bio = sh->orig_bio;
	sector_t end_lba = bio_end_sector(bio);

	if (bitmap_empty(ctx->dev_status, RAIZN_MAX_DEVS)) {
		return raizn_read_simple(sh);
	} else {
		int failed_dev_idx =
			find_first_bit(ctx->dev_status, RAIZN_MAX_DEVS);
		raizn_stripe_head_hold_completion(sh);
		for (sector_t stripe_lba = lba_to_stripe_addr(ctx, start_lba);
		     stripe_lba < bio_end_sector(sh->orig_bio);
		     stripe_lba += ctx->params->stripe_sectors) {
			int parity_dev_idx =
				lba_to_parity_dev_idx(ctx, stripe_lba);
			int failed_dev_su_idx =
				failed_dev_idx > parity_dev_idx ?
					failed_dev_idx - 1 :
					failed_dev_idx;
			sector_t start_su_idx = lba_to_su(ctx, start_lba) %
						ctx->params->stripe_width;
			//sector_t cur_stripe_start_lba = max(start_lba, stripe_lba);
			sector_t cur_stripe_end_lba =
				min(stripe_lba + ctx->params->stripe_sectors,
				    bio_end_sector(sh->orig_bio));
			sector_t end_su_idx =
				lba_to_su(ctx, cur_stripe_end_lba - 1) %
				ctx->params->stripe_width;
			int su_touched = max(
				(sector_t)1,
				end_su_idx -
					start_su_idx); // Cover edge case where only 1 stripe unit is involved in the IO
			bool stripe_degraded = false;
			struct bio *stripe_bio,
				*temp = bio_clone_fast(sh->orig_bio, GFP_NOIO,
						       &ctx->bioset);
			BUG_ON(!temp);
			if (temp->bi_iter.bi_sector < stripe_lba) {
				bio_advance(temp,
					    stripe_lba -
						    temp->bi_iter.bi_sector);
			}
			if (bio_end_sector(temp) > cur_stripe_end_lba) {
				stripe_bio = bio_split(
					temp,
					cur_stripe_end_lba -
						temp->bi_iter.bi_sector,
					GFP_NOIO, &ctx->bioset);
				bio_put(temp);
			} else {
				stripe_bio = temp;
			}
			stripe_bio->bi_private = NULL;
			stripe_bio->bi_end_io = NULL;
			BUG_ON(ctx->params->stripe_sectors == 0);
			// If the failed device is the parity device, the read can operate normally for this stripe
			// Or if the read starts on a stripe unit after the failed device, the read can operate normally for this stripe
			// Or if the read ends on a stripe unit before the failed device, the read can operate normally for this stripe
			stripe_degraded =
				parity_dev_idx != failed_dev_idx &&
				!(stripe_lba < start_lba &&
				  start_su_idx > failed_dev_su_idx) &&
				!((stripe_lba + ctx->params->stripe_sectors) >=
					  bio_end_sector(sh->orig_bio) &&
				  end_su_idx < failed_dev_su_idx);
			if (stripe_degraded) {
				sector_t failed_dev_su_start_lba =
					stripe_lba +
					failed_dev_su_idx *
						ctx->params->su_sectors;
				sector_t failed_dev_su_end_lba =
					failed_dev_su_start_lba +
					ctx->params->su_sectors;
				sector_t stripe_data_start_lba =
					max(stripe_lba, start_lba);
				sector_t stripe_data_end_lba =
					min(stripe_lba +
						    ctx->params->stripe_sectors,
					    bio_end_sector(sh->orig_bio));
				sector_t missing_su_start_offset = 0;
				sector_t missing_su_end_offset = 0;
				sh->op = RAIZN_OP_DEGRADED_READ;
				if (stripe_data_start_lba >
				    failed_dev_su_start_lba) {
					// If the stripe data starts in the middle of the failed dev SU
					missing_su_start_offset =
						stripe_data_start_lba -
						failed_dev_su_start_lba;
				}
				if (stripe_data_end_lba <
				    failed_dev_su_end_lba) {
					// If the stripe data ends in the middle of the failed dev SU
					missing_su_end_offset =
						failed_dev_su_end_lba -
						stripe_data_end_lba;
				}
				// Make sure each stripe unit in this stripe is read from missing_su_start_offset to missing_su_end_offset
				for (int su_idx = 0;
				     su_idx < ctx->params->stripe_width;
				     ++su_idx) {
					sector_t su_start_lba =
						stripe_lba +
						(su_idx *
						 ctx->params
							 ->su_sectors); // Theoretical
					sector_t su_data_required_start_lba =
						su_start_lba +
						missing_su_start_offset;
					sector_t su_data_required_end_lba =
						su_start_lba +
						ctx->params->su_sectors -
						missing_su_end_offset;
					sector_t num_sectors =
						su_data_required_end_lba -
						su_data_required_start_lba;
					struct raizn_dev *cur_dev =
						lba_to_dev(ctx, su_start_lba);
					struct raizn_sub_io *subio;
					if (cur_dev->idx == failed_dev_idx) {
						cur_dev =
							&ctx->devs[parity_dev_idx];
					}
					subio = raizn_stripe_head_alloc_bio(
						sh, &cur_dev->bioset, 1,
						RAIZN_SUBIO_REBUILD, NULL);
					BUG_ON(!subio);
					BUG_ON(!subio->bio);
					BUG_ON(!num_sectors);
					bio_set_op_attrs(subio->bio,
							 REQ_OP_READ, 0);
					bio_set_dev(subio->bio,
						    cur_dev->dev->bdev);
					subio->data = kmalloc(
						num_sectors << SECTOR_SHIFT,
						GFP_NOIO);
					BUG_ON(!subio->data);
					if (bio_add_page(
						    subio->bio,
						    virt_to_page(subio->data),
						    num_sectors << SECTOR_SHIFT,
						    offset_in_page(
							    subio->data)) !=
					    num_sectors << SECTOR_SHIFT) {
						pr_err("Failed to add extra pages for degraded read\n");
					}
					subio->bio->bi_iter
						.bi_sector = lba_to_pba_default(
						ctx,
						su_data_required_start_lba);
					subio->header.header.start =
						su_data_required_start_lba;
					subio->header.header.end =
						su_data_required_start_lba +
						bio_sectors(subio->bio);
					//ctx->counters.read_overhead += subio->header.size; // TODO add this back in
#ifdef SMALL_ZONE_AGGR
					raizn_submit_bio_aggr(ctx, __func__, subio->bio, cur_dev, 0);
#else					
					raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif					
				}
			}
			// Read the necessary stripe units normally
			for (; su_touched > 0; --su_touched) {
				struct raizn_dev *cur_dev = lba_to_dev(
					ctx, stripe_bio->bi_iter.bi_sector);
				sector_t su_end_lba = roundup(
					stripe_bio->bi_iter.bi_sector + 1,
					ctx->params->su_sectors);
				struct raizn_sub_io *su_subio;
				if (cur_dev->idx == failed_dev_idx) {
					if (bio_end_sector(stripe_bio) <=
					    su_end_lba) {
						break;
					}
					bio_advance(stripe_bio,
						    su_end_lba -
							    stripe_bio->bi_iter
								    .bi_sector);
					continue;
				}
				// Split the bio and read the failed stripe unit
				if (su_end_lba < bio_end_sector(stripe_bio)) {
					su_subio = raizn_stripe_head_add_bio(
						sh,
						bio_split(
							stripe_bio,
							su_end_lba -
								stripe_bio
									->bi_iter
									.bi_sector,
							GFP_NOIO,
							&cur_dev->bioset),
						RAIZN_SUBIO_REBUILD);
				} else {
					su_subio = raizn_stripe_head_add_bio(
						sh, stripe_bio,
						RAIZN_SUBIO_REBUILD);
					su_subio->defer_put = true;
				}
				bio_set_dev(su_subio->bio, cur_dev->dev->bdev);
				su_subio->bio->bi_iter
					.bi_sector = lba_to_pba_default(
					ctx, su_subio->bio->bi_iter.bi_sector);
#ifdef SMALL_ZONE_AGGR
				raizn_submit_bio_aggr(ctx, __func__, su_subio->bio, cur_dev, 0);
#else				
				raizn_submit_bio(ctx, __func__, su_subio->bio, 0);
#endif				
			}
		}
		raizn_stripe_head_release_completion(sh);
	}
	return DM_MAPIO_SUBMITTED;
}


// Returns the new zone PBA on success, -1 on failure
// This function invokes the garbage collector
// Caller is responsible for holding dev->lock
struct raizn_zone *raizn_swap_mdzone(struct raizn_stripe_head *sh,
				     struct raizn_dev *dev,
				     raizn_zone_type mdtype,
				     struct raizn_zone *old_md_zone)
{
	struct raizn_zone *new_md_zone;
	int foreground = 0, submitted = 0, ret, j;
	atomic_set(&old_md_zone->cond, BLK_ZONE_COND_FULL);
retry:
	if (!kfifo_out_spinlocked(&dev->free_zone_fifo, &new_md_zone, 1,
				  &dev->free_rlock)) {
		foreground = 1;
		pr_err("Fatal error, no metadata zones remain\n");
		new_md_zone = NULL;
		atomic_set(&old_md_zone->cond, BLK_ZONE_COND_FULL);
		if (!submitted) {
			struct raizn_stripe_head *gc_sh =
				raizn_stripe_head_alloc(sh->ctx, NULL, RAIZN_OP_GC);
			gc_sh->zone = old_md_zone;
			ret = kfifo_in_spinlocked(
				&gc_sh->zone->dev->gc_flush_workers.work_fifo, &gc_sh,
				1, &gc_sh->zone->dev->gc_flush_workers.wlock);
			if (!ret) {
				pr_err("ERROR: %s kfifo insert failed!\n", __func__);
				BUG_ON(1);
			}
			raizn_queue_gc(sh->ctx, gc_sh->zone->dev);
			submitted = 1;
		}

		printk("raizn_swap_mdzone waiting");
		usleep_range(10, 20);
		goto retry;
	}
	dev->md_zone[mdtype] = new_md_zone;
	new_md_zone->zone_type = mdtype;
	atomic64_set(&new_md_zone->mdzone_wp, 0);
	atomic_set(&old_md_zone->cond, BLK_ZONE_COND_FULL);

	if (!foreground) {
		struct raizn_stripe_head *gc_sh =
			raizn_stripe_head_alloc(sh->ctx, NULL, RAIZN_OP_GC);
		gc_sh->zone = old_md_zone;
		ret = kfifo_in_spinlocked(
			&gc_sh->zone->dev->gc_flush_workers.work_fifo, &gc_sh,
			1, &gc_sh->zone->dev->gc_flush_workers.wlock);
		if (!ret) {
			pr_err("ERROR: %s kfifo insert failed!\n", __func__);
			BUG_ON(1);
		}
		raizn_queue_gc(sh->ctx, gc_sh->zone->dev);
	}
	return new_md_zone;
}

// Returns the LBA that the metadata should be written at
// RAIZN uses zone appends, so the LBA will align to a zone start
static struct raizn_zone *raizn_md_lba(struct raizn_stripe_head *sh,
				       struct raizn_dev *dev,
				       raizn_zone_type mdtype,
				       sector_t md_sectors)
{
	struct raizn_zone *mdzone;
	unsigned int flags;
#if (defined PP_OUTPLACE)
	mutex_lock(&dev->lock);
#else
	spin_lock_irqsave(&dev->lock, flags);
#endif
	mdzone = dev->md_zone[mdtype];
	if (mdzone->capacity < atomic64_add_return(md_sectors, &mdzone->mdzone_wp)) {
		mdzone->pzone_wp = mdzone->start + atomic64_read(&mdzone->mdzone_wp);
		mdzone = raizn_swap_mdzone(sh, dev, mdtype, mdzone);
		if (mdzone == NULL)
			return NULL;
	}
	atomic_inc(&mdzone->refcount);
#if (defined PP_OUTPLACE)
	mutex_unlock(&dev->lock);
#else
	spin_unlock_irqrestore(&dev->lock, flags);
#endif
	return mdzone;
}

struct raizn_sub_io *raizn_alloc_md(struct raizn_stripe_head *sh,
					   sector_t lzoneno,
					   struct raizn_dev *dev,
					   raizn_zone_type mdtype, 
					   sub_io_type_t subio_type,
					   void *data,
					   size_t len)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_sub_io *mdio = raizn_stripe_head_alloc_bio(
		sh, &dev->bioset, data ? 2 : 1, subio_type, data);
	
	struct bio *mdbio = mdio->bio;
	struct page *p;
	sector_t sectors;
#if defined (DUMMY_HDR) && defined (PP_OUTPLACE)
	sectors =
		(round_up(len, PAGE_SIZE) + PAGE_SIZE) >>
			SECTOR_SHIFT; // TODO: does round_up round 0 to PAGE_SIZE?
#else
	if ((mdtype == RAIZN_ZONE_MD_GENERAL)) {
		sectors = (round_up(len, PAGE_SIZE) + PAGE_SIZE) >>	SECTOR_SHIFT; // TODO: does round_up round 0 to PAGE_SIZE?
	}
	else {
		sectors = (round_up(len, PAGE_SIZE)) >>	SECTOR_SHIFT; // TODO: does round_up round 0 to PAGE_SIZE?
	}
#endif
	struct raizn_zone *mdzone = raizn_md_lba(
		sh, dev, mdtype, sectors); // TODO: does round_up round 0 to PAGE_SIZE?
	BUG_ON(!mdzone);
	mdio->zone = mdzone;

	mdio->header.header.zone_generation =
		ctx->zone_mgr.gen_counts[lzoneno / RAIZN_GEN_COUNTERS_PER_PAGE]
			.zone_generation[lzoneno % RAIZN_GEN_COUNTERS_PER_PAGE];
	mdio->header.header.magic = RAIZN_MD_MAGIC;
	mdio->dbg = len;
	bio_set_op_attrs(mdbio, REQ_OP_ZONE_APPEND, 0);
	bio_set_dev(mdbio, dev->dev->bdev);
	mdbio->bi_iter.bi_sector = mdzone->start;
#if !(defined (DUMMY_HDR) && defined (PP_OUTPLACE))
	if ((mdtype == RAIZN_ZONE_MD_GENERAL))
#endif
	{
		p = is_vmalloc_addr(&mdio->header) ? vmalloc_to_page(&mdio->header) :
							virt_to_page(&mdio->header);
		if (bio_add_page(mdbio, p, PAGE_SIZE, offset_in_page(&mdio->header)) !=
			PAGE_SIZE) {
			pr_err("Failed to add md header page\n");
			bio_endio(mdbio);
			BUG_ON(1);
			return NULL;
		}
	}
	if ((data) && (subio_type != RAIZN_SUBIO_WP_LOG)) {
		p = is_vmalloc_addr(data) ? vmalloc_to_page(data) :
					    virt_to_page(data);
		if (bio_add_page(mdbio, p, len, 0) != len) {
			pr_err("Failed to add md data page\n");
			bio_endio(mdbio);
			BUG_ON(1);
			return NULL;
		}
	}
	return mdio;
}

// Header must not be null, but data can be null
// Returns 0 on success, nonzero on failure
int raizn_write_md(struct raizn_stripe_head *sh, sector_t lzoneno,
			  struct raizn_dev *dev, raizn_zone_type mdtype,
	   		  sub_io_type_t subio_type,
			  void *data, size_t len)
{
	struct raizn_sub_io *mdio =
		raizn_alloc_md(sh, lzoneno, dev, mdtype, subio_type, data, len);
#if defined (DUMMY_HDR) && defined (PP_OUTPLACE)
	if (!mdio) {
		pr_err("Fatal: Failed to write metadata\n");
		return -1;
	}
#else
	if (!mdio)
		return 0;
#endif
#ifdef RECORD_PP_AMOUNT
#if defined (DUMMY_HDR) && defined (PP_OUTPLACE)
	atomic64_add((len + PAGE_SIZE) >> SECTOR_SHIFT, &sh->ctx->pp_permanent);
#else
	atomic64_add((len) >> SECTOR_SHIFT, &sh->ctx->pp_permanent);
#endif
#endif
#ifdef TIMING
	uint64_t lba = mdio->bio->bi_iter.bi_sector;
	printk("pp %llu %d %d %d %llu %d\n", 
		ktime_get_ns(), smp_processor_id(), current->pid, get_dev_idx(sh->ctx, dev), lba, bio_sectors(mdio->bio));
#endif
#ifdef SMALL_ZONE_AGGR
	raizn_submit_bio_aggr(sh->ctx, __func__, mdio->bio, dev, 0);
#else
	raizn_submit_bio(sh->ctx, __func__, mdio->bio, 0);
#endif	
	return 0;
}

// Alloc bio starting at lba if it doesn't exist, otherwise add to existing bio
static struct bio *check_alloc_dev_bio(struct raizn_stripe_head *sh,
				       struct raizn_dev *dev, sector_t lba, sub_io_type_t sub_io_type)
{
	if (sh->bios[dev->idx] &&
	    sh->bios[dev->idx]->bi_vcnt >= RAIZN_MAX_BVECS) {
		sh->bios[dev->idx] = NULL;
	}
	if (!sh->bios[dev->idx]) {
		struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(
			sh, &dev->bioset, RAIZN_MAX_BVECS, sub_io_type, NULL);
		if (!subio) {
			pr_err("Failed to allocate subio\n");
		}
		sh->bios[dev->idx] = subio->bio;
		subio->dev = dev;
		subio->dev_idx = dev->idx;
		subio->bio->bi_opf = sh->orig_bio->bi_opf;
		subio->bio->bi_iter.bi_sector =
			lba_to_pba_default(sh->ctx, lba);
		bio_set_dev(subio->bio, dev->dev->bdev);
		subio->zone = &dev->zones[lba_to_lzone(sh->ctx, lba)];
	}
	return sh->bios[dev->idx];
}

int raizn_write(struct raizn_stripe_head *sh)
{
#ifdef DEBUG
	BUG_ON(in_interrupt());
#endif
	int num_xor_units = 0, i;
	struct raizn_ctx *ctx = sh->ctx;
	sector_t start_lba = sh->orig_bio->bi_iter.bi_sector;
	sh->lba = start_lba;
	sector_t end_lba = bio_end_sector(sh->orig_bio);
	sector_t start_su = lba_to_su(ctx, start_lba);
    sector_t end_su = lba_to_su(ctx, end_lba - 1);
	int start_stripe_id = lba_to_stripe(ctx, start_lba);
	int end_stripe_id = lba_to_stripe(ctx, end_lba - 1);
	int lzone_num = lba_to_lzone(ctx, start_lba);
	struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lzone_num];
	size_t su_bytes = ctx->params->su_sectors
			<< SECTOR_SHIFT;

#ifdef RECORD_PP_AMOUNT
	atomic64_add(bio_sectors(sh->orig_bio), &ctx->total_write_amount);
	atomic64_inc(&ctx->total_write_count);
#endif
	// End LBA of the first stripe in this IO
	sector_t leading_stripe_end_lba =
		min(lba_to_stripe_addr(ctx, start_lba) +
			    ctx->params->stripe_sectors,
		    end_lba);
	// Number of sectors in the leading partial stripe, 0 if the first stripe is full or the entire bio is a trailing stripe
	// A leading stripe starts in the middle of a stripe, and can potentially fill the remainder of the stripe
	// A trailing stripe starts at the beginning of a stripe and ends before the last LBA of the stripe
	// *If* the offset within the stripe is nonzero, we take the contents of the first stripe and treat it as a leading substripe
	sector_t leading_substripe_sectors =
		lba_to_stripe_offset(ctx, start_lba) > 0 ?
			leading_stripe_end_lba - start_lba :
			0;
	// Number of sectors in the trailing partial stripe, 0 if the last stripe is full or the entire bio is a leading stripe
	sector_t trailing_substripe_sectors =
		(bio_sectors(sh->orig_bio) - leading_substripe_sectors) %
		ctx->params->stripe_sectors;
	int full_parity_chunks = (end_stripe_id - start_stripe_id) 
		+ ((ctx->params->stripe_sectors - lba_to_stripe_offset(ctx, end_lba - 1) <= ctx->params->su_sectors) ? 1 : 0);
	int pp_chunks = 0;
    if (start_su == end_su) {  // non-spanning request. easy to handle
        if (!check_last_su(ctx, end_lba - 1)) { // for the last-seq chunk, FP will be directly written
			pp_chunks++;
		}
	}
	else {
        if (lba_to_su_offset(ctx, end_lba)) { // chunk-unaligned
		    sector_t end_su_start = (lba_to_su_offset(ctx, end_lba)) ?
				end_lba - lba_to_su_offset(ctx, end_lba) : 
				end_lba - ctx->params->su_sectors;
            if (!check_last_su(ctx, end_lba - 1))
				pp_chunks++;
            if (!check_last_su(ctx, end_su_start - 1)) 
				pp_chunks++;
		}
		else {
            if (!check_last_su(ctx, end_lba - 1)) // for the last-seq chunk, FP will be directly written
				pp_chunks++;
		}
	}

	struct bio *bio;
	struct bio_vec bv;
	struct bvec_iter iter;
	struct raizn_dev *dev;
	unsigned int op_flags =
		op_is_flush(bio_op(sh->orig_bio)) ?
			((sh->orig_bio->bi_opf & REQ_FUA) | REQ_PREFLUSH) :
			0;
	raizn_stripe_head_hold_completion(sh);
	BUG_ON(bio_sectors(sh->orig_bio) == 0);
	// Allocate buffer to hold all parity
	int parity_su = full_parity_chunks + pp_chunks;
	sh->parity_su = parity_su;
	if (parity_su == 0)
		BUG_ON(1);
#if 1
	// if (1)
	if (parity_su <= 1)
		sh->parity_bufs = mempool_alloc(ctx->parity_buf_mpool_1[lzone_num % ctx->params->mempool_num], GFP_NOIO);
	else if (parity_su <= 2)
		sh->parity_bufs = mempool_alloc(ctx->parity_buf_mpool_2[lzone_num % ctx->params->mempool_num], GFP_NOIO);
	else if (parity_su <= 4)
		sh->parity_bufs = mempool_alloc(ctx->parity_buf_mpool_4[lzone_num % ctx->params->mempool_num], GFP_NOIO);
	else if (parity_su <= 8)
		sh->parity_bufs = mempool_alloc(ctx->parity_buf_mpool_8[lzone_num % ctx->params->mempool_num], GFP_NOIO);
	else
		sh->parity_bufs = mempool_alloc(ctx->parity_buf_mpool_max[lzone_num % ctx->params->mempool_num], GFP_NOIO);

		/*
		// mempool_alloc(ctx->parity_buf_mpool[lzone_num % ctx->num_cpus], GFP_NOIO);
		*/
#else
		sh->parity_bufs = vzalloc(parity_su * (ctx->params->su_sectors << SECTOR_SHIFT));
		// sh->parity_bufs = kzalloc(parity_su * su_bytes, GFP_NOIO);
		// = mempool_alloc(ctx->parity_buf_mpool, GFP_NOIO);
#endif

	if (!sh->parity_bufs) {
		pr_err("Failed to allocate parity buffers\n");
		BUG_ON(1);
		return DM_MAPIO_KILL;
	}
	// Split off any partial stripes
	// Handle leading stripe units
	if (leading_substripe_sectors) {
		// Copy stripe data if necessary
		buffer_stripe_data(sh, start_lba, leading_stripe_end_lba);
#ifdef PP_OUTPLACE
		// if remaining is smaller than one chunk, full parity can be written instead of part parity
		if (ctx->params->stripe_sectors - lba_to_stripe_offset(ctx, leading_stripe_end_lba-1) >=  
				ctx->params->su_sectors) {
#ifndef IGNORE_PART_PARITY
			size_t leading_substripe_start_offset_bytes =
				lba_to_su_offset(ctx, start_lba)
				<< SECTOR_SHIFT;
			size_t leading_substripe_parity_bytes =
				min(ctx->params->su_sectors,
				    leading_substripe_sectors)
				<< SECTOR_SHIFT;
			// Calculate and submit partial parity if the entire bio is a leading stripe
			calc_parity(ctx, start_lba, sh->parity_bufs, 
				(lba_to_stripe_offset(ctx, leading_stripe_end_lba) >> ctx->params->su_shift) +
				(lba_to_su_offset(ctx, leading_stripe_end_lba) ? 1 : 0));
			raizn_write_md(
				sh,
				lzone_num,
				lba_to_parity_dev(ctx, start_lba),
				RAIZN_ZONE_MD_PARITY_LOG,
				RAIZN_SUBIO_PP_OUTPLACE,
				sh->parity_bufs +
					leading_substripe_start_offset_bytes,
				leading_substripe_parity_bytes);
#endif
		}
#endif
	}
	if (bio_sectors(sh->orig_bio) >
	    leading_substripe_sectors + trailing_substripe_sectors) {
		if (leading_substripe_sectors) {
			bio = bio_clone_fast(sh->orig_bio, GFP_NOIO,
					     &ctx->bioset);
			BUG_ON(!bio);
			bio_advance(bio,
				    leading_substripe_sectors << SECTOR_SHIFT);
		} else {
			bio = sh->orig_bio;
		}
		int full_str_num = (bio_sectors(sh->orig_bio) - (leading_substripe_sectors + trailing_substripe_sectors)) / ctx->params->stripe_sectors;
		for (i=0; i<full_str_num; i++)
			buffer_stripe_data(sh, 
				start_lba + leading_substripe_sectors + i*ctx->params->stripe_sectors, 
				start_lba + leading_substripe_sectors + (i+1)*ctx->params->stripe_sectors);
		if (leading_substripe_sectors) {
			bio_put(bio);
		}
	}
	if (trailing_substripe_sectors) {
		sector_t trailing_substripe_start_lba =
			bio_end_sector(sh->orig_bio) -
			trailing_substripe_sectors;
		size_t trailing_substripe_parity_bytes =
			min(ctx->params->su_sectors, trailing_substripe_sectors)
			<< SECTOR_SHIFT;
		// Copy stripe data if necessary
		buffer_stripe_data(sh, trailing_substripe_start_lba,
				   end_lba);

		// if remaining is smaller than one chunk, full parity can be written instead of part parity
		if (ctx->params->stripe_sectors - lba_to_stripe_offset(ctx, bio_end_sector(sh->orig_bio) - 1) >=  
				ctx->params->su_sectors) {
#ifndef IGNORE_PART_PARITY
#ifdef PP_OUTPLACE
			calc_parity(ctx, trailing_substripe_start_lba, sh->parity_bufs, 
				(lba_to_stripe_offset(ctx, bio_end_sector(sh->orig_bio)) >> ctx->params->su_shift) +
				(lba_to_su_offset(ctx, bio_end_sector(sh->orig_bio)) ? 1 : 0));
			raizn_write_md(
				sh, lzone_num,
				lba_to_parity_dev(ctx, trailing_substripe_start_lba),
				RAIZN_ZONE_MD_PARITY_LOG,
				RAIZN_SUBIO_PP_OUTPLACE,
				sh->parity_bufs +
					(parity_su - 1) * ctx->params->su_sectors,
				trailing_substripe_parity_bytes);
#endif
#endif
			}
	}
#ifndef IGNORE_PART_PARITY
#if defined (PP_INPLACE)
	raizn_write_pp(sh, parity_su);

#endif
#endif

	for (i=0; i<full_parity_chunks; i++) {
		calc_parity(ctx, start_lba + (i << ctx->params->stripe_shift), 
			sh->parity_bufs + su_bytes * (pp_chunks + i), 
			ctx->params->stripe_width);
	}

	// Go stripe by stripe, splitting the bio and adding parity
	// This handles data and parity for the *entire* bio, including leading and trailing substripes
	bio_for_each_bvec (bv, sh->orig_bio, iter) {
		size_t data_pos = 0;
		while (data_pos < bv.bv_len) {
			sector_t lba =
				iter.bi_sector + (data_pos >> SECTOR_SHIFT);
			int stripe_id = lba_to_stripe(ctx, lba);
			int i;
			size_t su_remaining_bytes =
				(round_up(lba + 1, ctx->params->su_sectors) -
				 lba)
				<< SECTOR_SHIFT;
			size_t chunk_bytes =
				min(su_remaining_bytes, bv.bv_len - data_pos);
			sector_t chunk_end_lba =
				lba + (chunk_bytes >> SECTOR_SHIFT);
			dev = lba_to_dev(ctx, lba);
			bio = check_alloc_dev_bio(sh, dev, lba, RAIZN_SUBIO_DATA);
			BUG_ON(!bio);
			BUG_ON(chunk_bytes == 0);
			bio->bi_opf |= op_flags;
			if (bio_add_page(bio, bv.bv_page, chunk_bytes,
					 bv.bv_offset + data_pos) <
			    chunk_bytes) {
				pr_err("Failed to add pages\n");
				goto submit;
			}
#ifndef IGNORE_FULL_PARITY
			// If we write the last sector of a stripe unit, add parity
			if ( (ctx->params->stripe_sectors - lba_to_stripe_offset(ctx, lba) <= ctx->params->su_sectors) ||
				unlikely(lba_to_lzone(ctx, lba) != lba_to_lzone(ctx, chunk_end_lba)) // the last chunk (lba_to_stripe_offset(ctx, lba) becomes 0 at the end of lzone)
			) {
				dev = lba_to_parity_dev(ctx, lba);
				bio = check_alloc_dev_bio(
					sh, dev,
					lba, RAIZN_SUBIO_FP);
#ifdef RECOVER_DEBUG
// #if 1
				printk("##parity bio add, dev: %d, lba: %d, pba: %llu, zone: %d, chunk_bytes: %d, bv.bv_offset + data_pos: %llu\n",
					lba_to_parity_dev_idx(ctx, lba), lba, lba_to_pba_default(ctx, lba),
					lba_to_lzone(ctx, lba), chunk_bytes, bv.bv_offset + data_pos);
#endif							
				struct page *p;
				void *data = sh->parity_bufs + (su_bytes * (pp_chunks + stripe_id - start_stripe_id) + (lba_to_su_offset(ctx, lba) << SECTOR_SHIFT));
				p = is_vmalloc_addr(data) ? vmalloc_to_page(data) :
					    virt_to_page(data);
#ifdef RECOVER_DEBUG
// #if 1
				{
					uint8_t *buffer = data;
					printk("[%s] %p\n", __func__, buffer);
					int BUFFER_SIZE = 16;
					int j, zero_count = 0;
					for (j = 0; j < BUFFER_SIZE; j++) {
						printk("%02X", buffer[j]);
					}
				}
#endif

				if (bio_add_page(bio, p,
						//  su_bytes, 0) < su_bytes) {
						 chunk_bytes, 0) < chunk_bytes) {
						// chunk_bytes, bv.bv_offset + data_pos) < chunk_bytes) {
					pr_err("Failed to add parity pages\n");
					goto submit;
				}
			}
#endif
			data_pos += chunk_bytes;
		}
	}
submit:
	for (int subio_idx = 0; subio_idx <= atomic_read(&sh->subio_idx);
	     ++subio_idx) {
		struct raizn_sub_io *subio = sh->sub_ios[subio_idx];
		struct raizn_zone *zone = subio->zone;
		struct block_device *nvme_bdev;
		sector_t start_lba;
		int zone_idx; 
		int ret;
		if ((subio->sub_io_type == RAIZN_SUBIO_DATA) ||
			(subio->sub_io_type == RAIZN_SUBIO_PP_INPLACE) ||
			(subio->sub_io_type == RAIZN_SUBIO_FP))  {
			int bio_len = bio_sectors(subio->bio); 
			while (!subio_ready2submit(subio, 
				(subio->sub_io_type == RAIZN_SUBIO_DATA) || (subio->sub_io_type == RAIZN_SUBIO_FP) 
				)) {
#ifndef PERF_MODE
// #if 1
				if (lzone->waiting_data_lba == subio->bio->bi_iter.bi_sector) {
					int wc  = atomic_read(&lzone->wait_count_data);
					if (wc>=100) {
						if (wc%1000000 == 0) {
							sector_t allowed_range;
							if ((subio->sub_io_type == RAIZN_SUBIO_DATA) || (subio->sub_io_type == RAIZN_SUBIO_FP))
        						allowed_range = ZRWASZ/2 - bio_sectors(subio->bio);
							else
        						allowed_range = ZRWASZ - bio_sectors(subio->bio);
							printk("[raizn_write][%d:%d] lba: %llu, len: %llu, dev: %d(%s), wp: %llu, pba: %llu, diff: %llu, ZRWASZ: %d, allowed_range: %llu\n", 
								lzone_num,
								lba_to_stripe(ctx, sh->orig_bio->bi_iter.bi_sector),
								sh->orig_bio->bi_iter.bi_sector, bio_sectors(subio->bio),
								get_bio_dev_idx(ctx, subio->bio),
								get_bio_dev_idx(ctx, subio->bio) == lba_to_parity_dev_idx(ctx, sh->orig_bio->bi_iter.bi_sector) ?
									"PARITY":"DATA",
								subio->zone->pzone_wp, subio->bio->bi_iter.bi_sector,
								subio->bio->bi_iter.bi_sector - subio->zone->pzone_wp, 
								ZRWASZ,
								allowed_range);		
						}
						if (wc%100 == 0)
		    				usleep_range(10, 20);  // ## MAYBE Important code
					}
					atomic_inc(&lzone->wait_count_data);
				}
				else {
					atomic_set(&lzone->wait_count_data, 0);
					// usleep_range(10, 20);
					lzone->waiting_data_lba = subio->bio->bi_iter.bi_sector;
				}
#endif

// #ifdef MQ_DEADLINE // ZRAID mq-deadline version (need to yield) --> maybe sleep() doesn't affect on performance
#ifdef PP_OUTPLACE // delay makes GC stall
// #if 1
		    	usleep_range(10, 20);
#else
				udelay(2);
#endif
			}
#ifdef TIMING
			if (op_is_write(bio_op(subio->bio))) {
				uint64_t lba = subio->bio->bi_iter.bi_sector;
				if (subio->sub_io_type == RAIZN_SUBIO_DATA)
					printk("data %llu %d %d %d %llu %d\n", 
						ktime_get_ns(), smp_processor_id(), current->pid, get_dev_idx(sh->ctx, subio->dev), lba, bio_sectors(subio->bio));
				else if (subio->sub_io_type == RAIZN_SUBIO_FP)
					printk("fp %llu %d %d %d %llu %d\n", 
						ktime_get_ns(), smp_processor_id(), current->pid, get_dev_idx(sh->ctx, subio->dev), lba, bio_sectors(subio->bio));
			}
#endif

#ifdef SMALL_ZONE_AGGR
			raizn_submit_bio_aggr(ctx, __func__, subio->bio, subio->dev, 0);
#else
			raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif

		}
	}
	/*if (op_is_flush(bio_op(sh->orig_bio))) {
		for_each_clear_bit(dev_idx, dev_bitmap, RAIZN_MAX_DEVS) {
			dev = &ctx->devs[dev_idx];
			if (dev_idx < ctx->params->array_width) {
				// submit flush subio
				struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(sh, &dev->bioset, 0, RAIZN_SUBIO_DATA);
				bio_set_op_attrs(subio->bio, REQ_OP_FLUSH, REQ_PREFLUSH);
				submit_bio_noacct(subio->bio);
			}
		}
	}*/
	raizn_stripe_head_release_completion(sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_flush(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	int dev_idx;
	atomic_set(&sh->refcount, ctx->params->array_width);
	BUG_ON(bio_sectors(sh->orig_bio) !=
	       sh->orig_bio->bi_iter.bi_size >> SECTOR_SHIFT);
	for (dev_idx = 0; dev_idx < ctx->params->array_width; ++dev_idx) {
		struct raizn_dev *dev = &ctx->devs[dev_idx];
		struct bio *clone =
			bio_clone_fast(sh->orig_bio, GFP_NOIO, &dev->bioset);
		clone->bi_iter.bi_sector = lba_to_pba_default(
			ctx, sh->orig_bio->bi_iter.bi_sector);
		clone->bi_iter.bi_size =
			bio_sectors(sh->orig_bio) / ctx->params->stripe_width;
		clone->bi_private = &sh->sentinel;
		clone->bi_end_io = comph_endio;
		bio_set_dev(clone, dev->dev->bdev);
#ifdef SMALL_ZONE_AGGR
		raizn_submit_bio_aggr(ctx, __func__, clone, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, clone, 0);
#endif
	}
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_open(struct raizn_stripe_head *sh)
{
	raizn_zone_mgr_execute(sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_close(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	unsigned int flags;
	int zoneno = lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector), j, ret;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
	raizn_stripe_head_hold_completion(sh);
	for (int devno = 0; devno < ctx->params->array_width; ++devno) {
		struct raizn_dev *dev = &ctx->devs[devno];
		struct raizn_zone *pzone = &dev->zones[zoneno];
		struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(
			sh, &dev->bioset, 1, RAIZN_SUBIO_DATA, NULL);
		subio->bio->bi_iter.bi_sector = lba_to_pba_default(
			ctx, sh->orig_bio->bi_iter.bi_sector);
		bio_set_op_attrs(subio->bio, REQ_OP_ZONE_CLOSE, 0);
		bio_set_dev(subio->bio, dev->dev->bdev);
#ifdef SMALL_ZONE_AGGR
		subio->bio->bi_iter.bi_size = (ctx->params->num_zone_aggr << ctx->params->aggr_chunk_shift) << SECTOR_SHIFT;
		raizn_submit_bio_aggr(ctx, __func__, subio->bio, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif
	}
	raizn_stripe_head_release_completion(sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_finish(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	unsigned int flags;
	int ret, j;
	int zoneno = lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector);
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
	raizn_stripe_head_hold_completion(sh);
	for (int devno = 0; devno < ctx->params->array_width; ++devno) {
		struct raizn_dev *dev = &ctx->devs[devno];
		struct raizn_zone *pzone = &dev->zones[zoneno];
		struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(
			sh, &dev->bioset, 1, RAIZN_SUBIO_DATA, NULL);
		subio->bio->bi_iter.bi_sector = lba_to_pba_default(
			ctx, sh->orig_bio->bi_iter.bi_sector);
		bio_set_op_attrs(subio->bio, REQ_OP_ZONE_FINISH, 0);
		bio_set_dev(subio->bio, dev->dev->bdev);
#ifdef SMALL_ZONE_AGGR
		subio->bio->bi_iter.bi_size = (ctx->params->num_zone_aggr << ctx->params->aggr_chunk_shift) << SECTOR_SHIFT;
		raizn_submit_bio_aggr(ctx, __func__, subio->bio, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif
		spin_lock_irqsave(&pzone->pzone_wp_lock, flags);
		pzone->pzone_wp = pzone->start + pzone->capacity;
		spin_unlock_irqrestore(&pzone->pzone_wp_lock, flags);
	}
	raizn_stripe_head_release_completion(sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_append(struct raizn_stripe_head *sh)
{
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_reset_bottom(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	unsigned int flags;
	int ret;
	int zoneno = lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector);
	raizn_stripe_head_hold_completion(sh);
	ctx->zone_mgr.gen_counts[zoneno / RAIZN_GEN_COUNTERS_PER_PAGE]
		.zone_generation[zoneno % RAIZN_GEN_COUNTERS_PER_PAGE] += 1;
	for (int devno = 0; devno < ctx->params->array_width; ++devno) {
		struct raizn_dev *dev = &ctx->devs[devno];
		struct raizn_zone *pzone = &dev->zones[zoneno];
		struct raizn_sub_io *subio = raizn_stripe_head_alloc_bio(
			sh, &dev->bioset, 1, RAIZN_SUBIO_DATA, NULL);
		subio->bio->bi_iter.bi_sector = lba_to_pba_default(
			ctx, sh->orig_bio->bi_iter.bi_sector);
		bio_set_op_attrs(subio->bio, REQ_OP_ZONE_RESET, 0);
		bio_set_dev(subio->bio, dev->dev->bdev);
#ifdef SMALL_ZONE_AGGR
		subio->bio->bi_iter.bi_size = (ctx->params->num_zone_aggr << ctx->params->aggr_chunk_shift) << SECTOR_SHIFT;
		raizn_submit_bio_aggr(ctx, __func__, subio->bio, dev, 0);
#else
		raizn_submit_bio(ctx, __func__, subio->bio, 0);
#endif
		spin_lock_irqsave(&pzone->pzone_wp_lock, flags);
		pzone->pzone_wp = pzone->start;
		spin_unlock_irqrestore(&pzone->pzone_wp_lock, flags);
	}
	raizn_stripe_head_release_completion(sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_reset_top(struct raizn_stripe_head *sh)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_dev *dev =
		lba_to_dev(ctx, sh->orig_bio->bi_iter.bi_sector);
	struct raizn_dev *parity_dev =
		lba_to_parity_dev(ctx, sh->orig_bio->bi_iter.bi_sector);
	int zoneno = lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector);
	struct raizn_stripe_head *log_sh =
		raizn_stripe_head_alloc(ctx, NULL, RAIZN_OP_ZONE_RESET_LOG);
	struct raizn_sub_io *devlog =
		raizn_alloc_md(sh, zoneno, dev, RAIZN_ZONE_MD_GENERAL, RAIZN_SUBIO_OTHER, NULL, 0);
	struct raizn_sub_io *pdevlog = raizn_alloc_md(
		sh, zoneno, parity_dev, RAIZN_ZONE_MD_GENERAL, RAIZN_SUBIO_OTHER, NULL, 0);
	raizn_stripe_head_hold_completion(log_sh);
	sh->op = RAIZN_OP_ZONE_RESET;
	log_sh->next = sh; // Defer the original stripe head
	BUG_ON(!devlog || !pdevlog);
	bio_set_op_attrs(devlog->bio, REQ_OP_ZONE_APPEND, REQ_FUA);
	bio_set_op_attrs(pdevlog->bio, REQ_OP_ZONE_APPEND, REQ_FUA);
	devlog->header.header.logtype = RAIZN_MD_RESET_LOG;
	pdevlog->header.header.logtype = RAIZN_MD_RESET_LOG;
	devlog->header.header.start = sh->orig_bio->bi_iter.bi_sector;
	pdevlog->header.header.start = sh->orig_bio->bi_iter.bi_sector;
	devlog->header.header.end =
		devlog->header.header.start + ctx->params->lzone_size_sectors;
	pdevlog->header.header.end =
		pdevlog->header.header.start + ctx->params->lzone_size_sectors;
#ifdef SMALL_ZONE_AGGR
	raizn_submit_bio_aggr(ctx, __func__, devlog->bio, dev, 0);
	raizn_submit_bio_aggr(ctx, __func__, pdevlog->bio, dev, 0);
#else
	raizn_submit_bio(ctx, __func__, devlog->bio, 0);
	raizn_submit_bio(ctx, __func__, pdevlog->bio, 0);
#endif	
	raizn_stripe_head_release_completion(log_sh);
	return DM_MAPIO_SUBMITTED;
}

int raizn_zone_reset_all(struct raizn_stripe_head *sh)
{
	return DM_MAPIO_SUBMITTED;
}

void raizn_handle_io_mt(struct work_struct *work)
{
	struct raizn_workqueue *wq =
		container_of(work, struct raizn_workqueue, work);
	struct raizn_stripe_head *sh;

#ifdef BATCH_WQ
	while (kfifo_out_spinlocked(&wq->work_fifo, &sh, 1, &wq->rlock)) {
		raizn_write(sh);
	}
#else
	kfifo_out_spinlocked(&wq->work_fifo, &sh, 1, &wq->rlock);
	raizn_write(sh);
#endif
}