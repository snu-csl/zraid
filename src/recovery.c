#include "zraid.h"
#include "util.h"
#include "comph.h"
#include "nvme_util.h"

#define RECOVERY_DEBUG_ZONE 0


int check_degraded(struct raizn_ctx *ctx, int *degraded_dev)
{
    // TODO: get from argv
#ifdef DEGRADE_TEST
    *degraded_dev = 0;
    return 1;
#endif

    return 0;
}

int find_first_chunk(struct raizn_ctc *ctx)
{
    
}

// prog is expressed as a sequence number of corresponding chunk (starts from 0)
// E.g.) 1st chunk of 1st stripe --> 0, last chunk of 3nd stripe = 3 * stripe_width - 1
int convert_wp_to_prog(struct raizn_ctx *ctx, int devno, int zoneno)
{
    int prog, stripeno, dev_seq, rel_dist;
    sector_t pzone_start = ctx->devs[devno].zones[zoneno].start;
    sector_t pzone_wp = ctx->devs[devno].zones[zoneno].pzone_wp;
#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("devno: %d, wp: %llu\n", devno, pzone_wp);
#endif

    if (pzone_wp == pzone_start) // no prog
        return 0;

    if (pzone_wp & (ctx->params->su_sectors - 1)) {
        // remnant exists, step 1
        rel_dist = 0;
    }
    else
        rel_dist = 1;

    stripeno = ((pzone_wp - 1 - pzone_start) >> ctx->params->su_shift);
    dev_seq = get_dev_sequence_by_pba(ctx, devno, pzone_wp - 1); // data dev seq: 0 ~ array_width -2, parity dev seq: array_width -1
#ifdef STRIPE_BASED_REC
    if ((dev_seq == ctx->params->array_width - 2) || (dev_seq == ctx->params->array_width - 1)) {
        prog = (stripeno + 1) * ctx->params->stripe_width;
    }
    else if ((dev_seq == ctx->params->array_width - 3) && (rel_dist == 1)) {
        prog = (stripeno + 1) * ctx->params->stripe_width;
    }
    else {
        prog = (stripeno) * ctx->params->stripe_width;
    }
#else
    if (dev_seq == ctx->params->array_width - 1) // parity dev
        prog = (stripeno + 1) * ctx->params->stripe_width;
    else
        prog = stripeno * ctx->params->stripe_width + dev_seq + rel_dist + 1; // +1 because the chunk in the dev_seq is totally included
#endif
#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("[convert_wp_to_prog] pzone_wp & (ctx->params->su_sectors - 1): %d, pzone_wp = %llu, stripeno: %d, dev_seq: %d, prog = %d\n"
            , pzone_wp & (ctx->params->su_sectors - 1), pzone_wp, 
            stripeno, dev_seq, prog);
#endif

    return prog;
}

// data size = chunk
sector_t __get_prog_lba_from_wp_log(struct raizn_ctx *ctx, void *data)
{
    struct wp_log_entry *entries = (struct wp_log_entry *)data;
    int i;
    sector_t max_prog_lba = 0;
    uint64_t max_time = 0;
    for (i=0; i<sector_to_block_addr(ctx->params->su_sectors); i++)
    {
        struct wp_log_entry entry = entries[i];
        if (entry.magic != WP_LOG_ENTRY_MAGIC)
            continue;

        if (entry.lba > max_prog_lba) {
            if (!(entry.timestamp > max_time)) {
                pr_err("WP log BUG! timestamp of larger lba is smaller than before");
            }
            max_prog_lba = entry.lba;
            max_time = entry.timestamp;
        }
    }
    return max_prog_lba;
}

sector_t get_prog_lba_from_wp_log(struct raizn_ctx *ctx, int zoneno, int start_stripeno)
{
    int i, j, dev_idx, stripeno;
    sector_t stripe_start_lba = start_stripeno * ctx->params->stripe_sectors;
    sector_t curr_prog_lba, max_prog_lba = 0;

    // Scan ZRWA-data (volatile) area. WP progress can be delayed than WP logging. 
    // Further stripes that have committed can exist over obtained stripeno from current WP 
    for (j=0; j<ctx->params->chunks_in_zrwa/2; j++) {
        stripeno = start_stripeno + j;
        // choose larger prog among two WP packs
        for (i = 0; i < 2; ++i) {
            if (i == 0)
                dev_idx = lba_to_parity_dev_idx(ctx, stripeno * ctx->params->stripe_sectors);
            else
                dev_idx = (lba_to_parity_dev_idx(ctx, stripeno * ctx->params->stripe_sectors) + 1) % ctx->params->array_width;

            sector_t pzone_start = ctx->devs[dev_idx].zones[zoneno].start;
            sector_t pba = pzone_start + ((stripeno + ctx->params->chunks_in_zrwa/2) << ctx->params->su_shift);
            struct raizn_dev *dev = &ctx->devs[dev_idx];
            struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
            void *data = kzalloc(
                ctx->params->su_sectors << SECTOR_SHIFT,
                GFP_NOIO);;
            bio_set_op_attrs(bio, REQ_OP_READ, 0);
            bio_set_dev(bio, dev->dev->bdev);
            if (bio_add_page(bio, virt_to_page(data), 
                ctx->params->su_sectors << SECTOR_SHIFT,
                        0) != 
                ctx->params->su_sectors << SECTOR_SHIFT) {
                pr_err("Fatal error: failed to add page to bio in get_prog_lba_from_wp_log(), dev_idx: %d, stripeno: %d, pba: %d\n",
                    dev_idx, stripeno, pba);
                kfree(data);
                return -1;
            }
            bio->bi_iter.bi_sector = pba;
        #ifdef SMALL_ZONE_AGGR
            if (raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1)) {
        #else
            if (raizn_submit_bio(ctx, __func__, bio, 1)) {
        #endif
                pr_err("Fatal error: failed to read WP log location, dev_idx: %d, stripeno: %d, pba: %d\n",
                    dev_idx, stripeno, pba);
                return -1;
            }
            bio_put(bio);

            curr_prog_lba = __get_prog_lba_from_wp_log(ctx, data);
            if (curr_prog_lba > max_prog_lba)
                max_prog_lba = curr_prog_lba;
            kfree(data);
        }
    }
    return max_prog_lba;
}

int recover_zone_state(struct raizn_ctx *ctx, int zoneno)
{
    int devno, curr_prog, max_prog = -1;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
    sector_t prog_lba = 0, wp_log_lba;
    // Step 1: find the most advanced WP device
    for (devno=0; devno<ctx->params->array_width; devno++) {
        curr_prog = convert_wp_to_prog(ctx, devno, zoneno);
        if (curr_prog > max_prog)
            max_prog = curr_prog;
    }
    prog_lba = (max_prog << ctx->params->su_shift) + lzone->start;

#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("step 1 prog: %llu\n", prog_lba);
#endif

    // Step 2: check WP logs ("first chunk" corner case also handled by WP log)
    wp_log_lba = get_prog_lba_from_wp_log(ctx, zoneno, 
        lba_to_stripe(ctx, prog_lba));
#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("step 2 prog: %llu\n", wp_log_lba);
#endif

    // Step 3: make in-memory WP states to be consistent
    if (wp_log_lba > prog_lba)
        prog_lba = wp_log_lba;

    atomic64_set(&lzone->lzone_wp, prog_lba);

#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("zone[%d] wp is set to %llu\n", zoneno, prog_lba);
#endif
    return 0;
}

int rebuild_full_stripe(struct raizn_ctx *ctx, int deg_dev, int zoneno, int stripeno)
{
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
    void *data =
        kzalloc(ctx->params->stripe_sectors << SECTOR_SHIFT, GFP_NOIO);
    void *xor_dst = 
        kzalloc(ctx->params->su_sectors << SECTOR_SHIFT, GFP_NOIO);
    sector_t stripe_start_lba = lzone->start + (stripeno * ctx->params->stripe_sectors);
    int devno, cnt = 0, i;
	for (devno = 0; devno < ctx->params->array_width; ++devno) {
        void *bio_data;
        if (devno == deg_dev)
            continue;
        else {
            bio_data =
                data +
                cnt * (ctx->params->su_sectors << SECTOR_SHIFT);
            cnt++;
        }
		struct raizn_dev *dev = &ctx->devs[devno];
		struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bio_set_dev(bio, dev->dev->bdev);
		if (bio_add_page(bio, virt_to_page(bio_data),
				 ctx->params->su_sectors << SECTOR_SHIFT,
				 0) !=
		    ctx->params->su_sectors << SECTOR_SHIFT) {
			pr_err("Fatal error: failed to add pages to rebuild read bio\n");
            return -1;
		}
		bio->bi_iter.bi_sector =
			lba_to_pba_default(ctx, stripe_start_lba);
#ifdef RECOVER_DEBUG            
        print_bio_info(ctx, bio, __func__);
#endif

#ifdef SMALL_ZONE_AGGR
		raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
#else
		raizn_submit_bio(ctx, __func__, bio, 1);
#endif

#ifdef RECOVER_DEBUG            
        if (zoneno == RECOVERY_DEBUG_ZONE) {
            printk("seq: %d\n", devno);
            print_buf_hex(bio_data);
        }
#endif
        bio_put(bio);
    }
	void *stripe_units[RAIZN_MAX_DEVS];
    for (i = 0; i < ctx->params->stripe_width; ++i) {
		stripe_units[i] = data +
				  i * (ctx->params->su_sectors << SECTOR_SHIFT);
	}
    xor_blocks(ctx->params->stripe_width,
        ctx->params->su_sectors << SECTOR_SHIFT, xor_dst,
        stripe_units);
#ifdef RECOVER_DEBUG            
    printk("xor\n", devno);
    print_buf_hex(xor_dst);
#endif

	struct raizn_dev *dev = &ctx->devs[deg_dev];
    struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
    bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
    bio_set_dev(bio, dev->dev->bdev);
    if (bio_add_page(bio, virt_to_page(xor_dst),
                ctx->params->su_sectors << SECTOR_SHIFT,
                0) !=
        ctx->params->su_sectors << SECTOR_SHIFT) {
        pr_err("Fatal error: failed to add pages to rebuild read bio\n");
        return -1;
    }
    bio->bi_iter.bi_sector =
        lba_to_pba_default(ctx, stripe_start_lba);
#ifdef RECOVER_DEBUG            
    print_bio_info(ctx, bio, __func__);
#endif    
#ifdef SMALL_ZONE_AGGR
    raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
#else
    raizn_submit_bio(ctx, __func__, bio, 1);
#endif
    bio_put(bio);

    kfree(xor_dst);
    kfree(data);

    return 0;
}

// ensure that deg_dev is included in the partial stripe
// TODO: DYN_PP_DIST recovery algorithm. Get enabled info from superblock
int rebuild_part_stripe(struct raizn_ctx *ctx, int deg_dev, int zoneno, int stripeno)
{
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
    sector_t lzone_wp = atomic64_read(&lzone->lzone_wp);
    void *data =
        kzalloc((ctx->params->su_sectors * ctx->params->array_width) << SECTOR_SHIFT, GFP_NOIO);
    void *xor_dst = 
        kzalloc(ctx->params->su_sectors << SECTOR_SHIFT, GFP_NOIO);
#ifdef RECOVER_DEBUG
    printk("DATA: %p, xor_dst: %p\n", data, xor_dst);
#endif
    sector_t stripe_start_lba = lzone->start + (stripeno * ctx->params->stripe_sectors);
    int start_chunk_idx = (lba_to_parity_dev_idx(ctx, lzone_wp - 1) + 1) % ctx->params->array_width;
    int end_chunk_idx = lba_to_dev_idx(ctx, lzone_wp - 1);
    int totcnt = get_dev_sequence_by_lba(ctx, lzone_wp - 1); // total chunks to read within the partial stripe
    sector_t tot_rebuild_sect; // sectors counts to be written
    int pp_idx = (end_chunk_idx + 1) % ctx->params->array_width;
    int pp_distance;
    sector_t pp_chunk_start_pba, read_lba;
    struct raizn_dev *dev;

    get_pp_distance(ctx, lzone_wp, &pp_distance);
    if (pp_distance >= 0) {
        pp_chunk_start_pba = lba_to_pba_default(ctx, stripe_start_lba) + (pp_distance << ctx->params->su_shift);
    }    
    else {
        //TODO get PP from SB zone
    }
#ifdef RECOVER_DEBUG
    printk("totcnt: %d,end_chunk_idx: %d, pp_idx: %d, pp_dist: %d, pp_chunk_start_pba: %llu\n", totcnt, end_chunk_idx, pp_idx, pp_distance, pp_chunk_start_pba);
#endif

    int devno = start_chunk_idx, cnt = 0, i;
    // step 1: read valid data chunks
    void *bio_data;
	while (cnt < totcnt) {
        sector_t read_sect = ctx->params->su_sectors;
#ifdef RECOVER_DEBUG
        printk("cnt: %d, devno: %d, deg_dev: %d, offset_in_page(bio_data): %d\n", cnt, devno, deg_dev, offset_in_page(bio_data));
#endif
        if (devno == deg_dev) {
            devno++;
            if (devno == ctx->params->array_width)
                devno = 0;
            continue;
        }
        else {
            bio_data =
                data +
                cnt * (ctx->params->su_sectors << SECTOR_SHIFT);
            cnt++;
        }

        if ((devno == end_chunk_idx) && lba_to_su_offset(ctx, lzone_wp) != 0)
            read_sect = lba_to_su_offset(ctx, lzone_wp);

#ifdef RECOVER_DEBUG
        printk("step 1 bio_data: %p\n", bio_data);
#endif
		dev = &ctx->devs[devno];
		struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bio_set_dev(bio, dev->dev->bdev);
		if (bio_add_page(bio, virt_to_page(bio_data),
				 read_sect << SECTOR_SHIFT,
				 0) !=
		    read_sect << SECTOR_SHIFT) {
			pr_err("Fatal error: failed to add pages to rebuild read bio\n");
		}
		bio->bi_iter.bi_sector =
			lba_to_pba_default(ctx, stripe_start_lba);
#ifdef RECOVER_DEBUG   
// #if 1         
        print_bio_info(ctx, bio, __func__);
#endif        

#ifdef SMALL_ZONE_AGGR
		raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
#else
		raizn_submit_bio(ctx, __func__, bio, 1);
#endif

#ifdef RECOVER_DEBUG
        if (zoneno == RECOVERY_DEBUG_ZONE) {
            printk("seq: %d\n", devno);
            print_buf_hex(bio_data);
        }
#endif
        bio_put(bio);

        devno++;
        if (devno == ctx->params->array_width)
            devno = 0;
    }

    // step 2: read 1st parity chunk
    dev = &ctx->devs[pp_idx];
    if (pp_idx == lba_to_parity_dev_idx(ctx, lzone_wp - 1))
        read_lba = lba_to_pba_default(ctx, stripe_start_lba); // read FP
    else
        read_lba = pp_chunk_start_pba; // read PP
    
    struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
    bio_data =
        data +
        totcnt * (ctx->params->su_sectors << SECTOR_SHIFT);
#ifdef RECOVER_DEBUG
    printk("step 2 bio_data: %p\n", bio_data);
#endif
    bio_set_op_attrs(bio, REQ_OP_READ, 0);
    bio_set_dev(bio, dev->dev->bdev);
    if (bio_add_page(bio, virt_to_page(bio_data),
                ctx->params->su_sectors << SECTOR_SHIFT,
                0) !=
        ctx->params->su_sectors << SECTOR_SHIFT) {
        pr_err("Fatal error: failed to add pages to rebuild read bio\n");
    }
    bio->bi_iter.bi_sector = read_lba;
#ifdef RECOVER_DEBUG
// #if 1            
    print_bio_info(ctx, bio, __func__);
#endif
#ifdef SMALL_ZONE_AGGR
    raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
#else
    raizn_submit_bio(ctx, __func__, bio, 1);
#endif

#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE) {
        printk("seq: %d\n", devno);
        print_buf_hex(bio_data);
    }
#endif
    bio_put(bio);

    // step 3: read 2nd part of parity chunk (if needed)
    if ((lba_to_su_offset(ctx, lzone_wp) != 0) && (totcnt > 0)) {
        if (pp_idx == 0) // rotate to back
            dev = &ctx->devs[ctx->params->stripe_width];
        else {
            dev = &ctx->devs[pp_idx - 1];
        }
        bio_data =
            data +
            (totcnt - 1) * (ctx->params->su_sectors << SECTOR_SHIFT) +
            (lba_to_su_offset(ctx, lzone_wp) << SECTOR_SHIFT); // append to the data
#ifdef RECOVER_DEBUG
        printk("step 3 bio_data: %p\n", bio_data);
#endif
        struct bio *bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
        bio_set_op_attrs(bio, REQ_OP_READ, 0);
        bio_set_dev(bio, dev->dev->bdev);
        if (bio_add_page(bio, virt_to_page(bio_data),
                (ctx->params->su_sectors - lba_to_su_offset(ctx, lzone_wp)) << SECTOR_SHIFT,
                0) !=
            (ctx->params->su_sectors - lba_to_su_offset(ctx, lzone_wp)) << SECTOR_SHIFT) {
            pr_err("Fatal error: failed to add pages to rebuild read bio\n");
        }
        bio->bi_iter.bi_sector = pp_chunk_start_pba + lba_to_su_offset(ctx, lzone_wp);
#ifdef RECOVER_DEBUG      
// #if 1      
        print_bio_info(ctx, bio, __func__);
#endif

    #ifdef SMALL_ZONE_AGGR
        raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
    #else
        raizn_submit_bio(ctx, __func__, bio, 1);
    #endif
 
#ifdef RECOVER_DEBUG
        if (zoneno == RECOVERY_DEBUG_ZONE) {
            print_buf_hex(bio_data);
        }
#endif
        bio_put(bio);
    }

#ifdef RECOVER_DEBUG
    {
        for (i=0; i<totcnt+1; i++) {
            uint8_t *buffer = data + i*(ctx->params->su_sectors << SECTOR_SHIFT) ;
            printk("%d: %p\n", i, buffer);
            buffer += + (8 << SECTOR_SHIFT) - 8;
            int BUFFER_SIZE = 16;
            int j, zero_count = 0;
            for (j = 0; j < BUFFER_SIZE; j++) {
                printk("%02X", buffer[j]);
            }
        }
    }

    // step 4: rebuild & write

    printk("totcnt: %d\n", totcnt);
#endif
    if (lba_to_su_offset(ctx, lzone_wp) != 0) { // rebuild with two parts
        if (deg_dev == end_chunk_idx) {
            tot_rebuild_sect = lba_to_su_offset(ctx, lzone_wp);
            void *stripe_units[RAIZN_MAX_DEVS];
            for (i = 0; i < totcnt+1; ++i) {
                stripe_units[i] = data +
                    i * (ctx->params->su_sectors << SECTOR_SHIFT);
            }

#ifdef RECOVER_DEBUG
            printk("xor1\n");
#endif
            xor_blocks(totcnt + 1,
                ctx->params->su_sectors << SECTOR_SHIFT,
                xor_dst,
                stripe_units);
                    
#ifdef RECOVER_DEBUG
            print_buf_hex(xor_dst);
#endif
        }
        else {
            tot_rebuild_sect = ctx->params->su_sectors;
            if (totcnt > 0) {
                void *stripe_units[RAIZN_MAX_DEVS];
                for (i = 0; i < totcnt+1; ++i) {
                    stripe_units[i] = data +
                        i * (ctx->params->su_sectors << SECTOR_SHIFT) +
                        (lba_to_su_offset(ctx, lzone_wp) << SECTOR_SHIFT);
                }
#ifdef RECOVER_DEBUG
                printk("xor2.1, %d\n", (lba_to_su_offset(ctx, lzone_wp) << SECTOR_SHIFT));
#endif
                xor_blocks(totcnt,
                    (ctx->params->su_sectors - lba_to_su_offset(ctx, lzone_wp)) << SECTOR_SHIFT, 
                    xor_dst + (lba_to_su_offset(ctx, lzone_wp) << SECTOR_SHIFT),
                    stripe_units);
                
#ifdef RECOVER_DEBUG
                print_buf_hex(xor_dst);
#endif
            }
            void *stripe_units[RAIZN_MAX_DEVS];
            for (i = 0; i < totcnt+1; ++i) {
                stripe_units[i] = data +
                    i * (ctx->params->su_sectors << SECTOR_SHIFT);
            }
#ifdef RECOVER_DEBUG
            printk("xor2.2\n");
#endif
            xor_blocks(totcnt + 1,
                lba_to_su_offset(ctx, lzone_wp) << SECTOR_SHIFT, 
                xor_dst,
                stripe_units);
#ifdef RECOVER_DEBUG
            print_buf_hex(xor_dst);
#endif

        }
    }
    else {
        // whole chunk rebuild
        tot_rebuild_sect = ctx->params->su_sectors;
        void *stripe_units[RAIZN_MAX_DEVS];
        for (i = 0; i < totcnt+1; ++i) {
            stripe_units[i] = data +
                i * (ctx->params->su_sectors << SECTOR_SHIFT);
        }
#ifdef RECOVER_DEBUG
        printk("xor3\n");
#endif
        xor_blocks(totcnt + 1,
            ctx->params->su_sectors << SECTOR_SHIFT, xor_dst,
            stripe_units);
#ifdef RECOVER_DEBUG
        print_buf_hex(xor_dst);
#endif
    }
    dev = &ctx->devs[deg_dev];
    bio = bio_alloc_bioset(GFP_NOIO, 1, &dev->bioset);
    bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
    bio_set_dev(bio, dev->dev->bdev);
    if (bio_add_page(bio, virt_to_page(xor_dst),
                tot_rebuild_sect << SECTOR_SHIFT,
                0) !=
        tot_rebuild_sect << SECTOR_SHIFT) {
        pr_err("Fatal error: failed to add pages to rebuild read bio\n");
        return -1;
    }
    bio->bi_iter.bi_sector =
        lba_to_pba_default(ctx, stripe_start_lba);
#ifdef RECOVER_DEBUG 
// #if 1           
    print_bio_info(ctx, bio, __func__);
#endif
#ifdef SMALL_ZONE_AGGR
    raizn_submit_bio_aggr(ctx, __func__, bio, dev, 1);
#else
    raizn_submit_bio(ctx, __func__, bio, 1);
#endif
    bio_put(bio);

    kfree(xor_dst);
    kfree(data);

    return 0;
}


int rebuild_zone(struct raizn_ctx *ctx, int deg_dev_idx, int zoneno)
{
    // if (zoneno != RECOVERY_DEBUG_ZONE) {
    //     return 0;
    // }

    int str_num;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[zoneno];
    sector_t lzone_wp = atomic64_read(&lzone->lzone_wp);

    if (lzone_wp == lzone->start)
        return 0;

    // step 1: identify crash-front stripe
    int cfront_stripe = lba_to_stripe(ctx, lzone_wp - 1);

#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("zoneno: %d, deg_dev_idx: %d, wp: %llu, cfront_str: %d\n", zoneno, deg_dev_idx, lzone_wp, cfront_stripe);
#endif

    // step 2: check the degraded device is in a partial stripe
    int cfront_dev_idx = lba_to_dev_idx(ctx, lzone_wp - 1);
    int parity_dev_idx = lba_to_parity_dev_idx(ctx, lzone_wp - 1);
    int cfront_seq = get_dev_sequence(ctx, cfront_dev_idx, parity_dev_idx);
    int deg_seq = get_dev_sequence(ctx, deg_dev_idx, parity_dev_idx);
    bool in_partial = (deg_seq <= cfront_seq);
    
#ifdef RECOVER_DEBUG
    if (zoneno == RECOVERY_DEBUG_ZONE)
        printk("parity_dev_idx: %d, deg_dev_idx: %d, deg_dev_seq: %d, cfront_dev_idx: %d, cfront_dev_seq: %d\n", 
            parity_dev_idx, deg_dev_idx, deg_seq, cfront_dev_idx, cfront_seq);
#endif

    // step 3: rebuild until just before the crash-front stripe
    for (str_num=0; str_num<cfront_stripe; str_num++) {
        rebuild_full_stripe(ctx, deg_dev_idx, zoneno, str_num);
    }

    // step 4: rebuild crash-front stripe
    if (lba_to_stripe_offset(ctx, lzone_wp) == 0)
        rebuild_full_stripe(ctx, deg_dev_idx, zoneno, cfront_stripe);
    else
        rebuild_part_stripe(ctx, deg_dev_idx, zoneno, cfront_stripe);


}

int reset_data_zone(struct raizn_ctx *ctx, int zoneno) {

}


int reset_data_zones(struct raizn_ctx *ctx)
{
    pr_info("Resetting data zones..\n");
    int zoneno, devno, ret;
    for (zoneno=0; zoneno<ctx->devs[0].num_zones-RAIZN_RESERVED_ZONES; zoneno++) {
        for (devno=0; devno<ctx->params->array_width; devno++) {
		    struct raizn_dev *dev = &ctx->devs[devno];
            sector_t zone_wp = dev->zones[zoneno].pzone_wp;
            if (zone_wp != 0) {
                sector_t zone_start = dev->zones[zoneno].start;
                if (ret = blkdev_zone_mgmt(dev->dev->bdev,
                    REQ_OP_ZONE_RESET,
                    zone_start,
                    dev->zones[0].len,
                    GFP_NOIO))
                    return ret;
            }
        }
    }
    pr_info("Resetting done\n");
    return 0;
}

int raizn_power_recovery(struct raizn_ctx *ctx, int boot_state)
{
#ifdef RECOVER_DEBUG
    printk("boot_state: %d\n", boot_state);
#endif
    int degraded_dev = -1;
    // if (!(boot_state & RAIZN_BOOT_SB)) {
    if (0) {
        // reset the data zone and restart the array
        return reset_data_zones(ctx);
    }
    else {
        int degraded = check_degraded(ctx, &degraded_dev);

        // iterate zone by zone, identify the most advanced physical WP, and set "logical WP" based on it.
        int zoneno;
        for (zoneno=0; zoneno<ctx->devs[0].num_zones-RAIZN_RESERVED_ZONES; zoneno++) {
            recover_zone_state(ctx, zoneno);
        }

        if (degraded) {
            for (zoneno=0; zoneno<ctx->devs[0].num_zones-RAIZN_RESERVED_ZONES; zoneno++) {
                rebuild_zone(ctx, degraded_dev, zoneno);
            }
        }

    }
    return 0;
}  

