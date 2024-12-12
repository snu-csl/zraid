#include <linux/delay.h>


#include "zraid.h"
#include "util.h"
#include "pp.h"
#include "comph.h"

void print_buf_hex(void *buf)
{
    const uint8_t *byteBuffer = (const uint8_t *)buf + (8 << SECTOR_SHIFT) - 8;
    for (int i = 0; i < 16; i++) {
        printk("%02X ", byteBuffer[i]);
    }
    printk("\n");
    
}

static void raizn_record_op(struct raizn_stripe_head *sh)
{
#ifdef PROFILING
	struct raizn_ctx *ctx = sh->ctx;
	if (sh->op == RAIZN_OP_GC) {
		atomic_inc(&ctx->counters.gc_count);
	} else {
		switch (bio_op(sh->orig_bio)) {
		case REQ_OP_READ:
			atomic_inc(&ctx->counters.reads);
			atomic64_add(bio_sectors(sh->orig_bio),
				     &ctx->counters.read_sectors);
			break;
		case REQ_OP_WRITE:
			atomic_inc(&ctx->counters.writes);
			atomic64_add(bio_sectors(sh->orig_bio),
				     &ctx->counters.write_sectors);
			break;
		case REQ_OP_ZONE_RESET:
			atomic_inc(&ctx->counters.zone_resets);
			break;
		case REQ_OP_FLUSH:
			atomic_inc(&ctx->counters.flushes);
			break;
		}
		if (sh->orig_bio->bi_opf & REQ_FUA) {
			atomic_inc(&ctx->counters.fua);
		}
		if (sh->orig_bio->bi_opf & REQ_PREFLUSH) {
			atomic_inc(&ctx->counters.preflush);
		}
	}
#else
	(void)sh->ctx;
	(void)sh;
#endif
}

inline void raizn_record_subio(struct raizn_stripe_head *sh, struct raizn_sub_io *subio)
{
	struct raizn_ctx *ctx = sh->ctx;
    u64 elapsed_time = ktime_get_ns() - subio->submit_time;
    if (subio->sub_io_type == RAIZN_SUBIO_DATA) {
        atomic64_add(elapsed_time, &ctx->subio_counters.d_t_tot);
        atomic64_inc(&(ctx->subio_counters.d_count)); // not working, don't know why. alternated with atomic64_add
    }
    else if (subio->sub_io_type == RAIZN_SUBIO_FP) {
        atomic64_add(elapsed_time, &ctx->subio_counters.fp_t_tot);
        atomic64_inc(&(ctx->subio_counters.fp_count));
    }
    else if (subio->sub_io_type == RAIZN_SUBIO_PP_INPLACE) {
        atomic64_add(elapsed_time, &ctx->subio_counters.pp_in_t_tot);
        atomic64_inc(&(ctx->subio_counters.pp_in_count));
    }
    else if (subio->sub_io_type == RAIZN_SUBIO_PP_OUTPLACE) {
        atomic64_add(elapsed_time, &ctx->subio_counters.pp_out_t_tot);
        atomic64_inc(&(ctx->subio_counters.pp_out_count));
    }
}

void raizn_print_subio_counter(struct raizn_ctx *ctx)
{
    printk("raizn_print_subio_counter");
    if (atomic64_read(&ctx->subio_counters.d_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.d_t_tot)/atomic64_read(&ctx->subio_counters.d_count);
        printk("---RAIZN_SUBIO_DATA---");
        printk("total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.d_count), avg_lat);
    }
    if (atomic64_read(&ctx->subio_counters.fp_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.fp_t_tot)/atomic64_read(&ctx->subio_counters.fp_count);
        printk("---RAIZN_SUBIO_FP---");
        printk("total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.fp_count), avg_lat);
    }
    if (atomic64_read(&ctx->subio_counters.pp_in_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.pp_in_t_tot)/atomic64_read(&ctx->subio_counters.pp_in_count);
        printk("---RAIZN_SUBIO_PP_INPLACE---");
        printk("total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.pp_in_count), avg_lat);
    }
    if (atomic64_read(&ctx->subio_counters.pp_out_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.pp_out_t_tot)/atomic64_read(&ctx->subio_counters.pp_out_count);
        printk("---RAIZN_SUBIO_PP_OUTPLACE---");
        printk("total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.pp_out_count), avg_lat);
    }
}

void raizn_print_zf_counter(struct raizn_ctx *ctx)
{
    printk("raizn_print_zrwa_flush_counter");
    if (atomic64_read(&ctx->subio_counters.zf_cmd_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.zf_cmd_t_tot)/atomic64_read(&ctx->subio_counters.zf_cmd_count);
        printk("---ZRWA_FLUSH_PER_CMD---");
        printk("num_total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.zf_cmd_count), avg_lat);
    }
    if (atomic64_read(&ctx->subio_counters.zf_wq_count)) {
        u64 avg_lat = atomic64_read(&ctx->subio_counters.zf_wq_t_tot)/atomic64_read(&ctx->subio_counters.zf_wq_count);
        printk("---ZRWA_FLUSH_WQ_ENQ2END---");
        printk("total: %lld, avg_lat(nsec): %lld\n", 
            atomic64_read(&ctx->subio_counters.zf_wq_count), avg_lat);
    }
    // if (atomic64_read(&ctx->subio_counters.pp_in_count)) {
    //     u64 avg_lat = atomic64_read(&ctx->subio_counters.pp_in_t_tot)/atomic64_read(&ctx->subio_counters.pp_in_count);
    //     printk("---RAIZN_SUBIO_PP_INPLACE---");
    //     printk("total: %lld, avg_lat(nsec): %lld\n", 
    //         atomic64_read(&ctx->subio_counters.pp_in_count), avg_lat);
    // }
    // if (atomic64_read(&ctx->subio_counters.pp_out_count)) {
    //     u64 avg_lat = atomic64_read(&ctx->subio_counters.pp_out_t_tot)/atomic64_read(&ctx->subio_counters.pp_out_count);
    //     printk("---RAIZN_SUBIO_PP_OUTPLACE---");
    //     printk("total: %lld, avg_lat(nsec): %lld\n", 
    //         atomic64_read(&ctx->subio_counters.pp_out_count), avg_lat);
    // }
}

void print_bio_info(struct raizn_ctx *ctx, struct bio *bio, char *funcname)
{
	if (bio==NULL) {
		printk("[print_bio_info] bio is NULL!!");
		return;
	}
    sector_t dev_lba = bio->bi_iter.bi_sector;
    sector_t stripe_start_lba = (dev_lba >> ctx->params->su_shift) * ctx->params->stripe_sectors;
	char rw[20], devtype[20];
    int dev_idx;
    struct raizn_dev *bio_dev;
    sector_t wp = 0;
	if (op_is_write(bio_op(bio)))
		strcpy(rw, "WRITE");
	else if ((bio_op(bio)) == REQ_OP_READ)
		strcpy(rw, "READ");
    else
		strcpy(rw, "OTHER");
    if (bio->bi_bdev!=NULL) {
        bio_dev = get_bio_dev(ctx, bio);
        if (bio_dev) {
            dev_idx = bio_dev->idx;
            wp = bio_dev->zones[pba_to_pzone(ctx, dev_lba)].pzone_wp;
        }
        else {
            strcpy(devtype, "ORIG_BIO");
            dev_idx = -2;
        }

        if (lba_to_parity_dev_idx(ctx, stripe_start_lba) == dev_idx)
            strcpy(devtype, "PARITY");
        else if (dev_idx != -1)
            strcpy(devtype, "DATA");
    }
    else {
        return;
        strcpy(devtype, "RAIZN_VIRTUAL");
        dev_idx = -1;
    }
	pr_err("(%d) [%s] err: %d, dev: %d(%s), op: %d, rw: %s, lba: %lld(KB), len: %dKB, wp: %lldKB, zone: %d, stripe: %d\n", 
		current->pid, funcname, bio->bi_status, dev_idx, devtype, bio_op(bio), rw,
		dev_lba/2, bio->bi_iter.bi_size/1024, wp/2,
        (dev_idx<0) ? lba_to_lzone(ctx, dev_lba): pba_to_pzone(ctx, dev_lba), 
        (dev_idx<0) ? lba_to_stripe(ctx, dev_lba): (dev_lba - bio_dev->zones[pba_to_pzone(ctx, dev_lba)].start >> ctx->params->su_shift));
}

inline int raizn_submit_bio(struct raizn_ctx *ctx, char *funcname, struct bio *bio, bool wait)
{
// #if 1
#ifdef DEBUG   
    sector_t dev_pba = bio->bi_iter.bi_sector;
    sector_t stripe_start_lba = (dev_pba >> ctx->params->su_shift) * ctx->params->stripe_sectors;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, stripe_start_lba)];
	char rw[10], devtype[10];
	if (bio==NULL) {
		printk("[raizn_submit_bio] bio is NULL!!");
		goto submit;
	}
	if (op_is_write(bio_op(bio)))
		strcpy(rw, "WRITE");
	else
		strcpy(rw, "READ");
	if (lba_to_parity_dev_idx(ctx, stripe_start_lba) == get_bio_dev(ctx, bio)->idx)
		strcpy(devtype, "PARITY");
	else
		strcpy(devtype, "DATA");

    // if ((lba_to_lzone(ctx, stripe_start_lba) == DEBUG_TARG_ZONE_1) // debug
    //     || (lba_to_lzone(ctx, stripe_start_lba) == DEBUG_TARG_ZONE_2)) // debug
    printk("(%d)[%d:%d] submit_bio from [%s] dev: %d(%s), rw: %s, pba: %lldKB, len: %dKB, last_comp_str: %d\n", 
        current->pid, lba_to_lzone(ctx, stripe_start_lba), lba_to_stripe(ctx, stripe_start_lba),
        funcname, get_bio_dev(ctx, bio)->idx, devtype, rw,
        dev_pba/2, bio->bi_iter.bi_size/1024,  lzone->last_complete_stripe);
#endif //DEBUG
#ifdef RECORD_SUBIO
    struct raizn_sub_io *subio = bio->bi_private;
    if (subio)
        subio->submit_time = ktime_get_ns();
#endif

			 
	// {
	// 	struct bvec_iter iter;
    // 	struct bio_vec bvec;
	// 	bio_for_each_segment(bvec, bio, iter) {
	// 		uint8_t *buffer = bvec_kmap_local(&bvec); 
	// 		printk("[%s] %p\n", __func__, buffer);
	// 		int BUFFER_SIZE = 16;
	// 		int j, zero_count = 0;
	// 		for (j = 0; j < BUFFER_SIZE; j++) {
	// 			printk("%02X", buffer[j]);
	// 		}
	// 	}
	// }

submit:
	if(unlikely(wait)) {
		return submit_bio_wait(bio);
	}
	else {
		return submit_bio_noacct(bio);
	}
}

#ifdef SMALL_ZONE_AGGR
inline int raizn_submit_bio_aggr(struct raizn_ctx *ctx, char *funcname, struct bio *bio, struct raizn_dev *dev, bool wait)
{
// #if 1
#ifdef DEBUG   
    int targ_zone = 0;
    BUG_ON((dev==NULL));
    int i;
    char rw[10], devtype[10];
    sector_t dev_pba = bio->bi_iter.bi_sector;
    sector_t stripe_start_lba = (dev_pba / ctx->params->su_sectors) * ctx->params->stripe_sectors;
    // if (lba_to_lzone(ctx, stripe_start_lba) == targ_zone) {
    if (1) {
        struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, stripe_start_lba)];
        if (bio==NULL) {
            printk("[raizn_submit_bio] bio is NULL!!");
            goto submit;
        }
        if (op_is_write(bio_op(bio)))
            strcpy(rw, "WRITE");
        else
            strcpy(rw, "READ");
        if (lba_to_parity_dev_idx(ctx, stripe_start_lba) == get_bio_dev(ctx, bio)->idx)
            strcpy(devtype, "PARITY");
        else
            strcpy(devtype, "DATA");

        // if ((lba_to_lzone(ctx, stripe_start_lba) == DEBUG_TARG_ZONE_1) // debug
        //     || (lba_to_lzone(ctx, stripe_start_lba) == DEBUG_TARG_ZONE_2)) // debug
        printk("(%d)[%d:%d] submit_bio from [%s] dev: %d(%s), rw: %s, pba: %lldKB, len: %dKB, op: %d, last_comp_str: %d\n", 
            current->pid, lba_to_lzone(ctx, stripe_start_lba), lba_to_stripe(ctx, stripe_start_lba),
            funcname, get_bio_dev(ctx, bio)->idx, devtype, rw,
            dev_pba/2, bio->bi_iter.bi_size/1024,  
            bio_op(bio), lzone->last_complete_stripe);
    }
#endif

	struct bio *split;
    int ret;
	sector_t append_pba;
    if (bio_op(bio) == REQ_OP_ZONE_APPEND) {
	    mutex_lock(&dev->lock);
        if ((dev->md_azone_wp + bio_sectors(bio)) > dev->zones[0].phys_len) {
            dev->md_azone_idx++;
            dev->md_azone_wp = bio_sectors(bio);
        }
        else
            dev->md_azone_wp += bio_sectors(bio);

        if (dev->md_azone_idx == ctx->params->num_zone_aggr) {
            struct raizn_zone *mdzone = &dev->zones[pba_to_pzone(ctx, bio->bi_iter.bi_sector)];
            atomic64_set(&mdzone->mdzone_wp, mdzone->capacity);
            dev->md_azone_idx = 0;
        }

	    mutex_unlock(&dev->lock);
		append_pba = bio->bi_iter.bi_sector + 
			(dev->md_azone_idx << ctx->params->aggr_chunk_shift);
		bio->bi_iter.bi_sector = 
			pba_to_aggr_addr(ctx, append_pba);
    }
	else {
		while (round_up(bio->bi_iter.bi_sector + 1, AGGR_CHUNK_SECTOR) <
			bio_end_sector(bio)) {
			sector_t su_boundary = round_up(bio->bi_iter.bi_sector + 1,
				AGGR_CHUNK_SECTOR);
			sector_t chunk_size = su_boundary - bio->bi_iter.bi_sector;

			split = bio_split(bio, chunk_size, GFP_NOIO, &dev->bioset);
			BUG_ON(split==NULL);
			bio_set_dev(split, dev->dev->bdev);
			split->bi_iter.bi_sector = 
				pba_to_aggr_addr(ctx, split->bi_iter.bi_sector);
// #if 1
#ifdef DEBUG   
		if (bio_op(bio) == REQ_OP_ZONE_RESET) {
			printk("dev[%d]: %p", dev->idx, dev);
			print_bio_info(ctx, split, "aggr 1");
		}
#endif
			bio_chain(split, bio);
			submit_bio_noacct(split);
    	}
    	bio->bi_iter.bi_sector =
        	pba_to_aggr_addr(ctx, bio->bi_iter.bi_sector);
	}
// #if 1
#ifdef DEBUG   
    if (bio_op(bio) == REQ_OP_ZONE_RESET) {
        printk("dev[%d]: %p", get_bio_dev_idx(ctx, bio), get_bio_dev(ctx, bio));
        print_bio_info(ctx, bio, "aggr 2");
    }
#endif
submit:
	if(unlikely(wait)) {
		return submit_bio_wait(bio);
	}
	else {
		return submit_bio_noacct(bio);
	}
}
#endif

inline bool subio_ready2submit(struct raizn_sub_io *subio, bool data)
{
    s64 subio_pba = subio->bio->bi_iter.bi_sector;
    s64 allowed_range, dist_from_durable;
    if (data)
        allowed_range = ZRWASZ/2 - bio_sectors(subio->bio);
    else {
        allowed_range = ZRWASZ - bio_sectors(subio->bio);
    }

	if ((s64)READ_ONCE(subio->zone->pzone_wp) <
		((s64)(subio->bio->bi_iter.bi_sector) - (s64)(allowed_range)))
		return false; 

    return true;
}

inline struct raizn_dev *get_bio_dev(struct raizn_ctx *ctx,
					    struct bio *bio)
{
	int i;
	for (i = 0; i < ctx->params->array_width; i++) {
		if (ctx->devs[i].dev->bdev->bd_dev == bio->bi_bdev->bd_dev) {
			return &ctx->devs[i];
		}
	}
	return NULL;
}

inline int get_dev_sequence(struct raizn_ctx *ctx, int dev_idx, int parity_idx)
{
	if (dev_idx > parity_idx)
        return (dev_idx - parity_idx - 1);
    else
        return (ctx->params->array_width - parity_idx + dev_idx) - 1;
}

inline int get_dev_idx_by_sequence(struct raizn_ctx *ctx, int stripe_start_lba, int seq)
{
    int parity_idx = lba_to_parity_dev_idx(ctx, stripe_start_lba);
	return (parity_idx + 1 + seq) % ctx->params->array_width; // seq starts from 0
}


// sequence starts from 0 ~ ends at array_width - 2
inline int get_dev_sequence_by_pba(struct raizn_ctx *ctx, int devno, sector_t pba)
{
    sector_t stripe_start_lba = (pba >> ctx->params->su_shift) * ctx->params->stripe_sectors;
    int parity_idx = lba_to_parity_dev_idx(ctx, stripe_start_lba);
    if (devno > parity_idx)
        return (devno - parity_idx - 1);
    else
        return (ctx->params->array_width - parity_idx + devno) - 1;
}


// sequence starts from 0 ~ ends at array_width - 2
inline int get_dev_sequence_by_lba(struct raizn_ctx *ctx, sector_t lba)
{
    int dev_idx = lba_to_dev_idx(ctx, lba), parity_idx = lba_to_parity_dev_idx(ctx, lba);
    if (dev_idx >= parity_idx)
        return (dev_idx - parity_idx - 1);
    else
        return (ctx->params->array_width - parity_idx + dev_idx) - 1;
}

inline int get_dev_idx(struct raizn_ctx *ctx,
					    struct raizn_dev *dev)
{
    int i;
	for (i = 0; i < ctx->params->array_width; i++) {
		if (ctx->devs[i].dev == dev) {
			return i;
		}
	}
	return -1;
}


inline int get_bio_dev_idx(struct raizn_ctx *ctx,
					    struct bio *bio)
{
    int i;
    if (!bio->bi_bdev)
        return -1;
	dev_t bd_dev = bio->bi_bdev->bd_dev;
	for (i = 0; i < ctx->params->array_width; i++) {
		if (ctx->devs[i].dev->bdev->bd_dev == bio->bi_bdev->bd_dev) {
			return i;
		}
	}
	return -1;
}



// From the beginning of the logical zone, which number stripe is LBA in
inline sector_t lba_to_stripe(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return (lba % (ctx->params->lzone_size_sectors)) /
	       ctx->params->stripe_sectors;
#else
	return (lba & (ctx->params->lzone_size_sectors - 1)) /
	       ctx->params->stripe_sectors;
#endif
}
// From the beginning of the logical zone, which number stripe unit is LBA in
inline sector_t lba_to_su(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return (lba % (ctx->params->lzone_size_sectors)) /
	       ctx->params->su_sectors;
#else
	return (lba & (ctx->params->lzone_size_sectors - 1)) >>
	       ctx->params->su_shift;
#endif
}

// return true if given lbas are in the same su
inline bool check_same_su(struct raizn_ctx *ctx, sector_t lba1, sector_t lba2)
{
    return ( (lba1 >> ctx->params->su_shift) == (lba2 >> ctx->params->su_shift) );
}

// return true if given lba is in the last su of the stripe
inline bool check_last_su(struct raizn_ctx *ctx, sector_t lba)
{
    return ( 
        (ctx->params->stripe_sectors - lba_to_stripe_offset(ctx, lba)) <= ctx->params->su_sectors
    );
}

// Physical addr (for each raw dev) to physical zone num
inline sector_t pba_to_pzone(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return lba / ctx->devs[0].zones[0].len;
#else
	return lba >> ctx->devs[0].zone_shift;
#endif
}   

// Which logical zone number is LBA in
inline sector_t lba_to_lzone(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return lba / ctx->params->lzone_size_sectors;
#else
	return lba >> ctx->params->lzone_shift;
#endif
}

// Which device (index of the device in the array) holds the parity for data written in the stripe containing LBA
// Assuming RAID5 scheme
inline int lba_to_parity_dev_idx(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef MOD_RAID4
    return ctx->params->array_width - 1;
#else
	return ctx->params->array_width - ((lba_to_stripe(ctx, lba) + lba_to_lzone(ctx, lba)) % ctx->params->array_width) - 1;
#endif
}
// Same as above, but returns the actual device object
struct raizn_dev *lba_to_parity_dev(struct raizn_ctx *ctx, sector_t lba)
{
	return &ctx->devs[lba_to_parity_dev_idx(ctx, lba)];
}
// Which device holds the data chunk associated with LBA
struct raizn_dev *lba_to_dev(struct raizn_ctx *ctx, sector_t lba)
{
	sector_t su_position = lba_to_su(ctx, lba) % ctx->params->stripe_width;
#ifndef IGNORE_FULL_PARITY
	// if (su_position >= lba_to_parity_dev_idx(ctx, lba)) {
	// 	su_position += 1;
	// }
    su_position = (lba_to_parity_dev_idx(ctx, lba) + su_position + 1) % ctx->params->array_width;
#endif
	return &ctx->devs[su_position];
}
// Which device holds the data chunk associated with LBA
inline int lba_to_dev_idx(struct raizn_ctx *ctx, sector_t lba)
{
	int su_position = lba_to_su(ctx, lba) % ctx->params->stripe_width;
#ifndef IGNORE_FULL_PARITY
	// if (su_position >= lba_to_parity_dev_idx(ctx, lba)) {
	// 	su_position += 1;
	// }
    su_position = (lba_to_parity_dev_idx(ctx, lba) + su_position + 1) % ctx->params->array_width;
#endif
	return su_position;
}
// What is the offset of LBA within the logical zone (in 512b sectors)
inline sector_t lba_to_lzone_offset(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return lba % (ctx->params->lzone_size_sectors);
#else
	return lba & (ctx->params->lzone_size_sectors - 1);
#endif
}
// What is the offset of LBA within the stripe (in 512b sectors)
inline sector_t lba_to_stripe_offset(struct raizn_ctx *ctx, sector_t lba)
{
	return lba_to_lzone_offset(ctx, lba) & (ctx->params->stripe_sectors - 1);
}
// What is the offset of LBA within the stripe unit (in 512b sectors)
inline sector_t lba_to_su_offset(struct raizn_ctx *ctx, sector_t lba)
{
	return lba_to_lzone_offset(ctx, lba) & (ctx->params->su_sectors - 1);
}
// Same as above, except in bytes instead of sectors
inline sector_t bytes_to_stripe_offset(struct raizn_ctx *ctx,
					      uint64_t ptr)
{
	return (ptr & ((ctx->params->lzone_size_sectors << SECTOR_SHIFT) - 1)) %
	       (ctx->params->stripe_sectors << SECTOR_SHIFT);
}
// Return the starting LBA for the stripe containing lba (in sectors)
inline sector_t lba_to_stripe_addr(struct raizn_ctx *ctx, sector_t lba)
{
#ifdef NON_POW_2_ZONE_SIZE
	return (lba_to_lzone(ctx, lba) * ctx->params->lzone_size_sectors) +
	       lba_to_stripe(ctx, lba) * ctx->params->stripe_sectors;
#else
    return (lba_to_lzone(ctx, lba) << ctx->params->lzone_shift) +
	       lba_to_stripe(ctx, lba) * ctx->params->stripe_sectors;
#endif
}

// Logical -> physical default mapping translation helpers
// Simple arithmetic translation from lba to pba,
// assumes all drives have the same zone cap and size
inline sector_t lba_to_pba_default(struct raizn_ctx *ctx, sector_t lba)
{
	sector_t zone_idx = lba_to_lzone(ctx, lba);
#ifdef NON_POW_2_ZONE_SIZE
	sector_t zone_offset = lba % (ctx->params->lzone_size_sectors);
#else
	sector_t zone_offset = lba & (ctx->params->lzone_size_sectors - 1);
#endif
	sector_t offset = zone_offset & (ctx->params->su_sectors - 1);
	sector_t stripe_id = zone_offset / ctx->params->stripe_sectors;
#ifdef NON_POW_2_ZONE_SIZE
	return (zone_idx * ctx->devs[0].zones[0].len) +
#else
	return (zone_idx << ctx->devs[0].zone_shift) +
#endif
	       stripe_id * ctx->params->su_sectors + offset;
}

#ifdef SMALL_ZONE_AGGR
// aggr zone idx (column)
inline sector_t pba_to_aggr_zone(struct raizn_ctx *ctx, sector_t pba)
{
#ifdef NON_POW_2_ZONE_SIZE
	sector_t pzone_offset = pba % (ctx->devs[0].zones[0].len);
#else
	sector_t pzone_offset = pba & (ctx->devs[0].zones[0].len - 1);
#endif
    return (pzone_offset >> ctx->params->aggr_chunk_shift) & (ctx->params->num_zone_aggr - 1);
}

inline sector_t pba_to_aggr_addr(struct raizn_ctx *ctx, sector_t pba)
{
    sector_t pzone_idx = pba_to_pzone(ctx, pba);

#ifdef NON_POW_2_ZONE_SIZE
	sector_t pzone_offset = pba % (ctx->devs[0].zones[0].len);
#else
	sector_t pzone_offset = pba & (ctx->devs[0].zones[0].len - 1);
#endif

    sector_t aggr_zone_idx = (pzone_offset / ctx->params->aggr_chunk_sector) & (ctx->params->num_zone_aggr - 1); // row num in 2-dimensional chunk array
	sector_t aggr_stripe_id = (pzone_offset / ctx->params->aggr_chunk_sector) >> ctx->params->aggr_zone_shift; // col num in 2-dimensional chunk array
	sector_t aggr_chunk_offset = pzone_offset & (ctx->params->aggr_chunk_sector - 1);

	return (pzone_idx * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len) + // pzone start
            aggr_zone_idx * ctx->devs[0].zones[0].phys_len + // aggr_zone start
            (aggr_stripe_id << ctx->params->aggr_chunk_shift) + 
            aggr_chunk_offset;
}
#endif

// block unit (= minimal read/write unit of real device, 4096b or etc.) to sector unit (512b)
inline sector_t block_to_sector_addr(sector_t block_addr)
{
    return (block_addr << DEV_BLOCKSHIFT) >> SECTOR_SHIFT;
}

inline sector_t sector_to_block_addr(sector_t sector_addr)
{
    return (sector_addr << SECTOR_SHIFT) >> DEV_BLOCKSHIFT;
}

inline void reset_stripe_buf(struct raizn_ctx *ctx, sector_t start, sector_t end)
{
    struct raizn_zone *lzone =
		&ctx->zone_mgr.lzones[lba_to_lzone(ctx, start)];
    int i;
    if (lzone->stripe_buffers) {
		for (i = lba_to_stripe(ctx, start); i<lba_to_stripe(ctx, end) - 1; i++) {
			struct raizn_stripe_buffer *buf =
				&lzone->stripe_buffers[i & STRIPE_BUFFERS_MASK];
			memset(buf->data, 0, ctx->params->stripe_sectors << SECTOR_SHIFT);
		}
    }
}

// partial parity from the starting chunk of the stripe to the chunk of end_lba
// lba is used to identify stripe buffer
// dst must be allocated and sufficiently large
// srcoff is the offset within the stripe
// Contents of dst are not included in parity calculation
void calc_parity(struct raizn_ctx *ctx,
					 sector_t lba, void *dst, int num_xor_units)
{
#ifdef RECOVER_DEBUG
	printk("calc_parity/ lba: %llu, num_xor_units: %d, dst: %p\n", lba, num_xor_units, dst);
#endif
    int i;
	void *stripe_units[RAIZN_MAX_DEVS];
	struct raizn_zone *lzone =
		&ctx->zone_mgr.lzones[lba_to_lzone(ctx, lba)];
	struct raizn_stripe_buffer *buf =
		&lzone->stripe_buffers[lba_to_stripe(ctx, lba) &
				       STRIPE_BUFFERS_MASK];
	for (i = 0; i < ctx->params->stripe_width; ++i) {
		stripe_units[i] = buf->data +
				  i * (ctx->params->su_sectors << SECTOR_SHIFT);
#ifdef RECOVER_DEBUG
// #if 1
		{
			uint8_t *buffer = stripe_units[i];
			printk("[%s] %d: %p\n", __func__, i, buffer);
			int BUFFER_SIZE = 16;
			int j, zero_count = 0;
			for (j = 0; j < BUFFER_SIZE; j++) {
				printk("%02X", buffer[j]);
			}
			// buffer = stripe_units[i] + 4096;
			// printk("[%s] %d: %p\n", __func__, i, buffer);
			// for (j = 0; j < BUFFER_SIZE; j++) {
			// 	printk("%02X", buffer[j]);
			// }
		}
#endif
	}
	xor_blocks(num_xor_units,
		   ctx->params->su_sectors << SECTOR_SHIFT, dst, stripe_units);
	return;
}

void raizn_stripe_head_hold_completion(struct raizn_stripe_head *sh)
{
	atomic_inc(&sh->refcount);
	sh->sentinel.bio = bio_alloc_bioset(GFP_NOIO, 0, &sh->ctx->bioset);
	sh->sentinel.bio->bi_end_io = comph_endio;
	sh->sentinel.bio->bi_private = &sh->sentinel;
}

void raizn_stripe_head_release_completion(struct raizn_stripe_head *sh)
{
	bio_endio(sh->sentinel.bio);
}


struct raizn_stripe_head *
raizn_stripe_head_alloc(struct raizn_ctx *ctx, struct bio *bio, raizn_op_t op)
{
	struct raizn_stripe_head *sh;
	sh = kzalloc(sizeof(struct raizn_stripe_head), GFP_NOIO);

	if (!sh) {
		return NULL;
	}
	sh->ctx = ctx;
	sh->orig_bio = bio;
	if (bio) {
		sh->zone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, sh->orig_bio->bi_iter.bi_sector)];
	}
	atomic_set(&sh->refcount, 0);
	atomic_set(&sh->subio_idx, -1);
	sh->op = op;
	sh->sentinel.sh = sh;
	sh->sentinel.sub_io_type = RAIZN_SUBIO_OTHER;
	sh->zf_submitted = false;
	return sh;
}


void raizn_stripe_head_free(struct raizn_stripe_head *sh)
{
	int lzone_num = lba_to_lzone(sh->ctx, sh->lba);
	int parity_su = sh->parity_su;
	struct raizn_ctx *ctx = sh->ctx;

	if (parity_su <= 1)
		mempool_free(sh->parity_bufs, ctx->parity_buf_mpool_1[lzone_num % ctx->params->mempool_num]);
	else if (parity_su <= 2)
		mempool_free(sh->parity_bufs, ctx->parity_buf_mpool_2[lzone_num % ctx->params->mempool_num]);
	else if (parity_su <= 4)
		mempool_free(sh->parity_bufs, ctx->parity_buf_mpool_4[lzone_num % ctx->params->mempool_num]);
	else if (parity_su <= 8)
		mempool_free(sh->parity_bufs, ctx->parity_buf_mpool_8[lzone_num % ctx->params->mempool_num]);
	else
		mempool_free(sh->parity_bufs, ctx->parity_buf_mpool_max[lzone_num % ctx->params->mempool_num]);

	if (sh->orig_bio) {
		for (int i = 0; i < RAIZN_MAX_SUB_IOS; ++i) {
			if (sh->sub_ios[i]) {
				struct raizn_sub_io *subio = sh->sub_ios[i];
				if (subio->defer_put) {
					bio_put(subio->bio);
				}
				kvfree(subio->data);
				kvfree(subio);
			} else {
				break;
			}
		}
	}
	kfree(sh);
}


struct raizn_sub_io *
raizn_stripe_head_alloc_subio(struct raizn_stripe_head *sh,
			      sub_io_type_t sub_io_type)
{
	struct raizn_sub_io *subio;
	int subio_idx = atomic_inc_return(&sh->subio_idx);
	atomic_inc(&sh->refcount);
	if (subio_idx >= RAIZN_MAX_SUB_IOS) {
		pr_err("Too many sub IOs generated, please increase RAIZN_MAX_SUB_IOS\n");
		return NULL;
	}
	subio = kzalloc(sizeof(struct raizn_sub_io), GFP_NOIO);
	BUG_ON(!subio);

	sh->sub_ios[subio_idx] = subio;
	subio->sub_io_type = sub_io_type;
	subio->sh = sh;
	return subio;
}

struct raizn_sub_io *
raizn_stripe_head_add_bio(struct raizn_stripe_head *sh, struct bio *bio,
			  sub_io_type_t sub_io_type)
{
	struct raizn_sub_io *subio =
		raizn_stripe_head_alloc_subio(sh, sub_io_type);
	subio->bio = bio;
	subio->bio->bi_end_io = comph_endio;
	subio->bio->bi_private = subio;
	return subio;
}

struct raizn_sub_io *
raizn_stripe_head_alloc_bio(struct raizn_stripe_head *sh,
			    struct bio_set *bioset, int bvecs,
			    sub_io_type_t sub_io_type, void *data)
{
	struct raizn_sub_io *subio;
#if (defined PP_OUTPLACE)
	if (1) // WARN: WP_LOG can't be written in outplace mode, concurrently it's not needed in outplace mode
#else
	if (sub_io_type != RAIZN_SUBIO_WP_LOG)
#endif
	{
		subio =
			raizn_stripe_head_alloc_subio(sh, sub_io_type);
		subio->bio = bio_alloc_bioset(GFP_NOIO, bvecs, bioset);
		BUG_ON(subio->bio == NULL);
	}
	else {
		subio = data;
		subio->bio = bio_alloc_bioset(GFP_NOIO, bvecs, bioset);
		BUG_ON(subio->bio == NULL);
		subio->sub_io_type = RAIZN_SUBIO_WP_LOG;
		atomic_inc(&sh->refcount);
	}
	subio->bio->bi_end_io = comph_endio;
	subio->bio->bi_private = subio;
	return subio;
}


// add bio data into lzone->stripe_buffer
int buffer_stripe_data(struct raizn_stripe_head *sh, sector_t start,
			      sector_t end)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_zone *lzone =
		&ctx->zone_mgr.lzones[lba_to_lzone(ctx, start)];
	struct raizn_stripe_buffer *buf =
		&lzone->stripe_buffers[lba_to_stripe(ctx, start) &
				       STRIPE_BUFFERS_MASK];

	sector_t len = end - start;
	size_t bytes_copied = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *pos =
		buf->data + (lba_to_stripe_offset(ctx, start) << SECTOR_SHIFT);
	struct bio *clone =
		bio_clone_fast(sh->orig_bio, GFP_NOIO, &ctx->bioset);
	if (start - sh->orig_bio->bi_iter.bi_sector > 0) {
		bio_advance(clone, (start - sh->orig_bio->bi_iter.bi_sector)
					   << SECTOR_SHIFT);
	}
	mutex_lock(&buf->lock);
	bio_for_each_bvec (bv, clone, iter) {
		uint8_t *data = bvec_kmap_local(&bv);
		size_t copylen =
			min((size_t)bv.bv_len,
			    (size_t)(len << SECTOR_SHIFT) - bytes_copied);
		memcpy(pos, data, copylen);
		kunmap_local(data);
		pos += copylen;
		bytes_copied += copylen;
		if (bytes_copied >= len << SECTOR_SHIFT) {
			break;
		}
	}
#ifdef RECOVER_DEBUG
// #if 1
	printk("buffer_stripe_data/ start_lba: %llu,  end_lba: %llu, str: %d,  buf: %p\n",  start, end, lba_to_stripe(ctx, start), buf->data);
		{
			uint8_t *buffer = buf->data;
			printk("[%s]  %p\n", __func__,  buffer);
			int BUFFER_SIZE = 16;
			int j, zero_count = 0;
			for (j = 0; j < BUFFER_SIZE; j++) {
				printk("%02X", buffer[j]);
			}
		}
#endif
	bio_put(clone);
	mutex_unlock(&buf->lock);
	return 0;
}

// dst must be allocated and sufficiently large
// srcoff is the offset within the stripe
// Contents of dst are not included in parity calculation
size_t raizn_stripe_buffer_parity(struct raizn_ctx *ctx,
					 sector_t start_lba, void *dst)
{
	int i;
	void *stripe_units[RAIZN_MAX_DEVS];
	struct raizn_zone *lzone =
		&ctx->zone_mgr.lzones[lba_to_lzone(ctx, start_lba)];
	struct raizn_stripe_buffer *buf =
		&lzone->stripe_buffers[lba_to_stripe(ctx, start_lba) &
				       STRIPE_BUFFERS_MASK];
	for (i = 0; i < ctx->params->stripe_width; ++i) {
		stripe_units[i] = buf->data +
				  i * (ctx->params->su_sectors << SECTOR_SHIFT);
	}

	xor_blocks(ctx->params->stripe_width,
		   ctx->params->su_sectors << SECTOR_SHIFT, dst, stripe_units);
	return 0;
}

// xor bio with pre-calculated part parity
// xor bio
// dst must be allocated and sufficiently large (always a multiple of stripe unit size)
int raizn_bio_parity(struct raizn_ctx *ctx, struct bio *src, void *dst)
{
	sector_t start_lba = src->bi_iter.bi_sector;
	uint64_t stripe_offset_bytes = lba_to_stripe_offset(ctx, start_lba)
				       << SECTOR_SHIFT;
	uint64_t su_bytes = (ctx->params->su_sectors << SECTOR_SHIFT);
	uint64_t stripe_bytes = (ctx->params->stripe_sectors << SECTOR_SHIFT);
	struct bvec_iter iter;
	struct bio_vec bv;
	bio_for_each_bvec (bv, src, iter) {
		uint8_t *data = bvec_kmap_local(&bv);
		uint8_t *data_end = data + bv.bv_len;
		uint8_t *data_itr = data;
		void *stripe_units[RAIZN_MAX_DEVS];
		size_t su_offset = stripe_offset_bytes & (su_bytes - 1);
		uint64_t su_remaining_bytes =
			su_offset > 0 ? su_bytes - su_offset : 0;
		// Finish the first partial stripe unit
		while (su_remaining_bytes > 0 && data_itr < data_end) {
			uint8_t *border =
				min(data_itr + su_remaining_bytes, data_end);
			size_t chunk_nbytes = border - data_itr;

			uint64_t pos_offset_bytes =
				(stripe_offset_bytes / stripe_bytes) *
					su_bytes +
				su_offset;
			stripe_units[0] = data_itr;
			stripe_units[1] = dst + pos_offset_bytes;
			xor_blocks(2, chunk_nbytes, dst + pos_offset_bytes,
				   stripe_units);
			data_itr += chunk_nbytes;
			stripe_offset_bytes += chunk_nbytes;
			su_offset = stripe_offset_bytes % su_bytes;
			su_remaining_bytes =
				su_offset > 0 ? su_bytes - su_offset : 0;
		}
		// data_itr is aligned on su boundary
		// Finish first partial stripe
		if (data_end >= data_itr + su_bytes &&
		    stripe_offset_bytes % stripe_bytes > 0) {
			size_t stripe_remaining_bytes =
				stripe_bytes -
				(stripe_offset_bytes % stripe_bytes);
			uint64_t pos_offset_bytes =
				(stripe_offset_bytes / stripe_bytes) * su_bytes;
			size_t num_su, i;
			uint8_t *border = data_itr + stripe_remaining_bytes;
			while (border > data_end)
				border -= su_bytes;
			num_su = (border - data_itr) / su_bytes;
			for (i = 0; i < num_su; i++)
				stripe_units[i] = data_itr + i * su_bytes;
			stripe_units[num_su] = dst + pos_offset_bytes;
			xor_blocks(num_su + 1, su_bytes, dst + pos_offset_bytes,
				   stripe_units);
			stripe_offset_bytes += num_su * su_bytes;
			data_itr += num_su * su_bytes;
		}
		// Step 3: Go stripe by stripe, XORing it into the buffer
		while (data_itr + stripe_bytes <= data_end) {
			uint64_t pos_offset_bytes =
				(stripe_offset_bytes / stripe_bytes) * su_bytes;
			int i;
			for (i = 0; i < ctx->params->stripe_width; i++) {
				stripe_units[i] = data_itr + i * su_bytes;
			}
			xor_blocks(ctx->params->stripe_width, su_bytes,
				   dst + pos_offset_bytes, stripe_units);
			data_itr += stripe_bytes;
			stripe_offset_bytes += stripe_bytes;
		}
		// Step 4: consume all of the remaining whole stripe units
		if (data_end >= data_itr + su_bytes) {
			size_t i;
			size_t num_su =
				min((size_t)((data_end - data_itr) / su_bytes),
				    (size_t)(ctx->params->array_width - 2));
			uint64_t pos_offset_bytes =
				(stripe_offset_bytes / stripe_bytes) * su_bytes;
			for (i = 0; i < num_su; i++)
				stripe_units[i] = data_itr + i * su_bytes;
			stripe_units[num_su] = dst + pos_offset_bytes;
			xor_blocks(num_su + 1, su_bytes, dst + pos_offset_bytes,
				   stripe_units);
			data_itr += num_su * su_bytes;
			stripe_offset_bytes += num_su * su_bytes;
		}
		// Step 5: go from the end of the last stripe unit border to the mid stripe border, XOR it into the buffer
		if (data_end - data_itr > 0) {
			uint64_t pos_offset_bytes =
				(stripe_offset_bytes / stripe_bytes) * su_bytes;
			size_t chunk_nbytes = data_end - data_itr;
			stripe_units[0] = data_itr;
			stripe_units[1] = dst + pos_offset_bytes;
			xor_blocks(2, chunk_nbytes, dst + pos_offset_bytes,
				   stripe_units);
			stripe_offset_bytes += chunk_nbytes;
		}
		kunmap_local(data);
	}
	return 0;
}



