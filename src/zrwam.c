#include "zraid.h"
#include "pp.h"
#include "util.h"
#include "nvme_util.h"

/* Below are manage functions */
void print_bitmap(struct raizn_ctx *ctx, struct raizn_zone *lzone)
{
    unsigned long *bitmap = lzone->stripe_prog_bitmap;
    unsigned long i, j, k;
    // mutex_lock(&lzone->prog_bitmap_lock);
    for (i=0; i<ctx->params->stripes_in_stripe_prog_bitmap; i++) {
        printk("stripe bitmap [%d] addr: %p\n", i, bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)));
        for (j=0; j<( BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors))); j++) {
            for (k=0; k<8; k++) {
                printk("%llu%llu%llu%llu%llu%llu%llu%llu\n",
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+0))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+1))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+2))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+3))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+4))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+5))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+6))) ? 1 : 0,
                    ((*(bitmap + i *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+7))) ? 1 : 0
                );
            }
        }
    }
    // mutex_unlock(&lzone->prog_bitmap_lock);
}

void print_bitmap_one_stripe(struct raizn_ctx *ctx, struct raizn_zone *lzone, int stripe_num)
{
    int stripe_idx = stripe_num % ctx->params->stripes_in_stripe_prog_bitmap;
    unsigned long *bitmap = lzone->stripe_prog_bitmap;
    unsigned long i, j, k;
    // mutex_lock(&lzone->prog_bitmap_lock);
    printk("stripe bitmap [%d] addr: %p\n", stripe_num, bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)));
    for (j=0; j<( BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors))); j++) {
        for (k=0; k<8; k++) {
            printk("%llu%llu%llu%llu%llu%llu%llu%llu\n",
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+0))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+1))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+2))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+3))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+4))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+5))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+6))) ? 1 : 0,
                ((*(bitmap + stripe_idx *  BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + j)) & (1LL<<(k*8+7))) ? 1 : 0
            );
        }
    }
    // mutex_unlock(&lzone->prog_bitmap_lock);
}

// wait until given stripe becomes durable. bitmap is checked from the start of the stripe to the end_offset
inline void wait_stripe_durable(struct raizn_ctx *ctx, struct raizn_zone *lzone, int stripe_num, int check_end_offset)
{
    int i;
    volatile unsigned long content = 0;
    volatile unsigned long *bitmap = lzone->stripe_prog_bitmap;
    unsigned long mask = (unsigned long)((unsigned long)1 << (unsigned long)sector_to_block_addr(check_end_offset)) - 1;
    int stripe_idx = stripe_num % ctx->params->stripes_in_stripe_prog_bitmap;
    char bit_pattern[64];

    for(i=0; i<BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)); i++)
    {
        content = READ_ONCE(*(bitmap + stripe_idx * BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + i));
        while (1) {
            if ((content & mask) == mask)
                break;
            if (READ_ONCE(lzone->last_complete_stripe)>=stripe_num)
                break;
            if ((atomic_read(&lzone->cond) != BLK_ZONE_COND_IMP_OPEN)&&(atomic_read(&lzone->cond) != BLK_ZONE_COND_EXP_OPEN))
                return; // zone is finished
            content = READ_ONCE(*(bitmap + stripe_idx * BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors)) + i));
// #ifndef PERF_MODE
#if 1
            if (lzone->waiting_str_num2 == stripe_num) {
                int wc  = atomic_read(&lzone->wait_count2);
                if (wc>=1000) {
                    if (wc%100000 == 0) {
                        convert_bit_pattern_64(mask - (content & mask), bit_pattern);
                        printk("[wait_stripe_durable] not match bit(%s)! stripe[%d:%d] %p: %llu, mask: %llu, &: %llu", 
                            bit_pattern,
                            lba_to_lzone(ctx, lzone->start),
                            stripe_num, 
                            bitmap + stripe_idx * BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors) + i),
                            content,
                            mask,
                            content & mask);
                    }
                }
                atomic_inc(&lzone->wait_count2);
            }
            else {
                atomic_set(&lzone->wait_count2, 0);
                lzone->waiting_str_num2 = stripe_num;
            }
#endif
            usleep_range(10, 20);
        }
    }
}


// wait all previous requests are persisted.
void zrwam_wait_prog(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba)
{ 
    int start_stripe_num = lba_to_stripe(ctx, start_lba);
    int end_stripe_num = lba_to_stripe(ctx, end_lba - 1);
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, start_lba)];
    int stripe_num, start_offset = 0, check_end_offset = 0;

    // wait until last completed stripe reaches at end_stripe_num -1
    while (1) {
        if (READ_ONCE(lzone->last_complete_stripe) >= end_stripe_num - 1) {
            break;
        }
        int zone_cond = atomic_read(&lzone->cond);
        if ((zone_cond != BLK_ZONE_COND_IMP_OPEN)&&(zone_cond != BLK_ZONE_COND_EXP_OPEN)) {
            return; // zone is finished
        }
// #ifndef PERF_MODE
#if 1
        if (lzone->waiting_str_num == end_stripe_num) {
            int wc  = atomic_read(&lzone->wait_count);
            if (wc>=1000) {
                if (wc%100000 == 0) {
                    int i, j;
                    unsigned long content = 0;
                    volatile unsigned long *bitmap = lzone->stripe_prog_bitmap;
                    char bit_pattern[64];
                    for (i=lzone->last_complete_stripe+1; i<=lzone->last_complete_stripe+5; i++) {
                        for (j=0;j<BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors));j++) {
                            content = READ_ONCE(*(bitmap + (i%ctx->params->stripes_in_stripe_prog_bitmap) * BITS_TO_LONGS(sector_to_block_addr(ctx->params->stripe_sectors))+j));
                            convert_bit_pattern_64(content, bit_pattern);
                            printk("[zrwam_wait_prog] stripe[%d:%d] %s\n", 
                                lba_to_lzone(ctx, lzone->start),
                                i, 
                                bit_pattern);
                        }
                    }
                }
            }
            atomic_inc(&lzone->wait_count);
        }
        else {
            atomic_set(&lzone->wait_count, 0);
            lzone->waiting_str_num = end_stripe_num;
        }
#endif
        usleep_range(10, 20);
    }
    if (start_stripe_num != end_stripe_num)
        return; // bitmap progress end stripe is already filled by this request
    
    // check until start_lba. this needs only when request is included in single stripe
    check_end_offset = lba_to_stripe_offset(ctx, start_lba); 
    if (check_end_offset != 0)
        wait_stripe_durable(ctx, lzone, end_stripe_num, check_end_offset);
}

// given lba is converted to corresponding pba in each dev
static void __zrwam_do_zrwa_flush(struct raizn_ctx *ctx, int dev_idx, sector_t dev_pba, bool to_parity)
{
#ifdef SAMSUNG_MODE
	struct block_device *nvme_bdev = ctx->raw_bdev;
    int pzone_idx = pba_to_pzone(ctx, dev_pba);
#else
	struct block_device *nvme_bdev = ctx->devs[dev_idx].dev->bdev;
#endif
	int ret, j;
    bool need_free = 0;
    unsigned long flags;
    struct raizn_zone *pzone = &ctx->devs[dev_idx].zones[pba_to_pzone(ctx, dev_pba)];
    if (dev_pba+1 >= pzone->start + pzone->capacity) {
        goto wp_update;
    }

	//  no need to submit zrwa flush, already flushed to former address by following request
	if (pzone->pzone_wp > dev_pba) {
        // do nothing
	}
    else {
    #ifdef RECORD_ZFLUSH
        u64 before = ktime_get_ns();
    #endif
        struct nvme_passthru_cmd *nvme_cmd = kzalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);
        if (!nvme_cmd) {
            printk("cmd alloc failed!");
            BUG_ON(1);
            return;
        }
        need_free = 1;
#ifdef SAMSUNG_MODE
		sector_t pzone_base_addr = dev_idx * ctx->params->div_capacity +
			(pzone_idx * ctx->params->gap_zone_aggr * ctx->devs[0].zones[0].phys_len);
#ifdef NON_POW_2_ZONE_SIZE
	    sector_t pzone_offset = dev_pba % (ctx->devs[0].zones[0].len);
#else
	    sector_t pzone_offset = dev_pba & (ctx->devs[0].zones[0].len - 1);
#endif
	    sector_t aggr_chunk_offset = pzone_offset & (ctx->params->aggr_chunk_sector - 1);
	    sector_t aggr_stripe_id = (pzone_offset / ctx->params->aggr_chunk_sector) >> ctx->params->aggr_zone_shift; // col num in 2-dimensional chunk array
        int azone_idx = pba_to_aggr_zone(ctx, dev_pba);
        int old_azone_idx = pba_to_aggr_zone(ctx, pzone->pzone_wp);
        sector_t cmd_addr;

        if ((dev_pba - pzone->pzone_wp) >= 
            (ctx->params->num_zone_aggr << (ctx->params->su_shift - 1))) {
            for (j=azone_idx; j<=azone_idx; j++) {
                if (j <= azone_idx)
                    cmd_addr = pzone_base_addr + j * ctx->devs[0].zones[0].phys_len +
                        (aggr_stripe_id << ctx->params->aggr_chunk_shift) +
                        aggr_chunk_offset;
                else
                    cmd_addr = pzone_base_addr + j * ctx->devs[0].zones[0].phys_len +
                        (aggr_stripe_id << ctx->params->aggr_chunk_shift) +
                        aggr_chunk_offset -
                        (ctx->params->su_sectors >> 1);
             
                zrwa_flush_zone(nvme_cmd, sector_to_block_addr(cmd_addr), NS_NUM, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
                ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_cmd);
                if (ret != 0) {
                    printk("(%d)[Fail]\tzrwa flush zone[%d:%d] ret: %d, dev: %d, pba(sector): %lld, pba: %lldKB, wp: %lldKB\n",
                        current->pid, pba_to_pzone(ctx, dev_pba), j, ret, 
                        dev_idx, cmd_addr-pzone->start, (cmd_addr-pzone->start)/2, (pzone->pzone_wp-pzone->start)/2);
                }
            }
        }
        else {
            if (old_azone_idx > azone_idx) { 
                for (j=azone_idx; j<=azone_idx; j++) {
                    cmd_addr = pzone_base_addr + j * ctx->devs[0].zones[0].phys_len +
                        (aggr_stripe_id << ctx->params->aggr_chunk_shift) +
                        aggr_chunk_offset;

                    zrwa_flush_zone(nvme_cmd, sector_to_block_addr(cmd_addr), NS_NUM, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
                    ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_cmd);
                    if (ret != 0) {
                        printk("(%d)[Fail]\tzrwa flush zone[%d:%d] ret: %d, dev: %d, pba(sector): %lld, pba: %lldKB, wp: %lldKB\n",
                            current->pid, pba_to_pzone(ctx, dev_pba), j, ret, 
                            dev_idx, cmd_addr-pzone->start, (cmd_addr-pzone->start)/2, (pzone->pzone_wp-pzone->start)/2);
                    }
                }
            }
            else {
                for (j=azone_idx; j<=azone_idx; j++) {
                    cmd_addr = pzone_base_addr + j * ctx->devs[0].zones[0].phys_len +
                        (aggr_stripe_id << ctx->params->aggr_chunk_shift) +
                        aggr_chunk_offset;

                    zrwa_flush_zone(nvme_cmd, sector_to_block_addr(cmd_addr), NS_NUM, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
                    ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_cmd);
                    if (ret != 0) {
                        printk("(%d)[Fail]\tzrwa flush zone[%d:%d] ret: %d, dev: %d, pba(sector): %lld, pba: %lldKB, wp: %lldKB\n",
                            current->pid, pba_to_pzone(ctx, dev_pba), j, ret, 
                            dev_idx, cmd_addr-pzone->start, (cmd_addr-pzone->start)/2, (pzone->pzone_wp-pzone->start)/2);
                    }
                }
            }
        }
#else // SAMSUNG_MODE
	    zrwa_flush_zone(nvme_cmd, sector_to_block_addr(dev_pba), NS_NUM, 0); // 3rd parameter is nsid of device e.g.) nvme0n2 --> 2
        ret = nvme_submit_passthru_cmd_sync(nvme_bdev, nvme_cmd);
#ifdef RECORD_ZFLUSH
        u64 elapsed_time = ktime_get_ns() - before;
        atomic64_add(elapsed_time, &ctx->subio_counters.zf_cmd_t_tot);
        atomic64_inc(&(ctx->subio_counters.zf_cmd_count));
#endif
        if (ret != 0) {
            printk("(%d)[Fail]\tzrwa flush zone[%d] ret: %d, dev: %d, pba(sector): %lld, pba: %lldKB, wp: %lldKB\n",
                current->pid, pba_to_pzone(ctx, dev_pba), ret, 
                dev_idx, dev_pba-pzone->start, (dev_pba-pzone->start)/2, (pzone->pzone_wp-pzone->start)/2);
        }
#endif // SAMSUNG_MODE
wp_update:
        spin_lock(&pzone->pzone_wp_lock);
        sector_t p_wp = READ_ONCE(pzone->pzone_wp);
        if (p_wp < min(dev_pba + 1, pzone->start + pzone->capacity)) {
            WRITE_ONCE(pzone->pzone_wp, min(dev_pba + 1, pzone->start + pzone->capacity));
        }
        spin_unlock(&pzone->pzone_wp_lock);
        if (need_free)
            kfree(nvme_cmd);
    }
}

void zrwam_do_zrwa_flush(struct raizn_stripe_head *sh, sector_t start_lba, sector_t end_lba)
{
    struct raizn_ctx *ctx = sh->ctx;
    zrwam_wait_prog(ctx, start_lba, end_lba);

    sector_t flush_lba_1, flush_lba_2;
    int zone_idx = lba_to_lzone(ctx, start_lba);
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zone_idx];
    struct raizn_zone *pzone = &ctx->devs[0].zones[zone_idx];
    sector_t pzone_start = pzone->start;
    int end_su_num, i, prev_dev_idx = -1, curr_dev_idx = -1;
    sector_t endsu_last_sector;
    int stripe_num, start_stripe_num, end_stripe_num;
    bool end_dev_is_first;

    endsu_last_sector = ((end_lba >> ctx->params->su_shift) << ctx->params->su_shift) - 1;
    start_stripe_num = lba_to_stripe(ctx, start_lba);  
    end_stripe_num = lba_to_stripe(ctx, endsu_last_sector);
    end_dev_is_first = (get_dev_sequence_by_lba(ctx, endsu_last_sector) == 0);

    if (end_dev_is_first) {
        // end_lba lies on the first chunk of a stripe.
        // the WP of previous stripe's last chunk should be advanced
        sector_t prev_str_first_sector = lba_to_stripe_addr(ctx, end_stripe_num - 1);
        curr_dev_idx = (lba_to_dev_idx(ctx, endsu_last_sector));
        prev_dev_idx = lba_to_parity_dev_idx(ctx, prev_str_first_sector) - 1;
        if (prev_dev_idx < 0) {
            prev_dev_idx += ctx->params->array_width;
        }
    }
    else {
        curr_dev_idx = (lba_to_dev_idx(ctx, endsu_last_sector));
        prev_dev_idx = (curr_dev_idx - 1);
        if (prev_dev_idx < 0) {
            prev_dev_idx += ctx->params->array_width;
        }
    }
    
    // advance WP to 2nd step (prev device). Only exception: the first chunk
    if (likely((lba_to_lzone_offset(ctx, endsu_last_sector))> ctx->params->su_sectors)) { // except first chunk of the zone (corner case)
        if (end_dev_is_first)
            flush_lba_1 = pzone_start + (end_stripe_num << ctx->params->su_shift) - 1; // prev stripe, step 2
        else
            flush_lba_1 = pzone_start + (end_stripe_num + 1 << ctx->params->su_shift) - 1; // step 2
        __zrwam_do_zrwa_flush(ctx, prev_dev_idx, flush_lba_1, false);
    }
    else if (unlikely((lba_to_lzone_offset(ctx, end_lba)) == ctx->params->su_sectors)) {
        struct raizn_stripe_head *dummy_sh = raizn_stripe_head_alloc(
            ctx, NULL, RAIZN_OP_WP_LOG);
        for (i=0; i<2; i++)
            raizn_stripe_head_alloc_subio(dummy_sh, RAIZN_SUBIO_WP_LOG); // need to allocate subio for two wp_logs
        raizn_write_wp_log(dummy_sh, end_lba);
    }

    // advance WP to 1st step (curr device)
    flush_lba_2 = pzone_start + (end_stripe_num << ctx->params->su_shift)
                    + (ctx->params->su_sectors >> 1) - 1; // step 1, half of the chunk
    __zrwam_do_zrwa_flush(ctx, curr_dev_idx, flush_lba_2, false);

    // if stripe(s) is complete, the bitmap for this stripe should be initialized & reused
    if (start_stripe_num != lba_to_stripe(ctx, end_lba)) {
        // stripe(s) is completed. advance lagging WPs
        end_stripe_num = (lba_to_stripe_offset(ctx, endsu_last_sector + 1) == 0) ? // is the stripe end chunk?
            end_stripe_num :
            end_stripe_num - 1;

        int dev_idx, flush_start_idx = get_dev_idx_by_sequence(ctx, endsu_last_sector, ctx->params->array_width - 3); // always start from this device (last - 1). crash consistency! (unprotected partial stripe can be recognized)
        flush_lba_1 = pzone_start + (end_stripe_num + 1 << ctx->params->su_shift) - 1; // step 2
		for (i=0; i<ctx->params->array_width; i++) { 
            dev_idx = (flush_start_idx + i) % ctx->params->array_width;
            if ((dev_idx==prev_dev_idx) || (dev_idx==curr_dev_idx))
                continue; // already advanced
            pzone = &ctx->devs[dev_idx].zones[zone_idx];
            if (pzone->pzone_wp < flush_lba_1) // else already flushed before
            {
                if (i == 1) // second rep, which is about the last-sequence dev in the stripe --> step 1
                    __zrwam_do_zrwa_flush(ctx, dev_idx, flush_lba_1 - (ctx->params->su_sectors >> 1), false);
                else
                    __zrwam_do_zrwa_flush(ctx, dev_idx, flush_lba_1, false);
            }
		}
    }

#ifdef RECORD_ZFLUSH
    if (sh->zf_submitted) {
        u64 elapsed_time = ktime_get_ns() - sh->zf_submit_time;
        atomic64_add(elapsed_time, &ctx->subio_counters.zf_wq_t_tot);
        atomic64_inc(&(ctx->subio_counters.zf_wq_count));
    }
#endif
}