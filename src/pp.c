#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/init.h>
#include <linux/bitmap.h>
#include <linux/bio.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/nvme_ioctl.h>
#include <linux/blkdev.h>
#include <linux/smp.h>
#include <linux/log2.h>

#include "zraid.h"
#include "pp.h"
#include "util.h"
#include "nvme_util.h"
#include "iosub.h"

inline void convert_bit_pattern_64(unsigned long num, char* bit_pattern)
{
    int i;
    for(i=63; i>=0; i--) {
        bit_pattern[i] = (num & 1) + '0';
        num >>= 1;
    }
}

// return: 1 if pp can be written in same lzone (common case), 0 if pp should be redirected to reserved zone (the last stripe)
// distance between PP & the write target position is stored in argument <distance>
inline int get_pp_distance(struct raizn_ctx *ctx, sector_t end_lba, int *pp_distance)
{
    sector_t ret;
    struct raizn_zone *lzone = &ctx->zone_mgr.lzones[lba_to_lzone(ctx, end_lba - 1)];
    sector_t rem2end = lzone->start + ctx->params->lzone_capacity_sectors - end_lba;
    // TODO: configurable 1/2 recursive algorithm implementation
    if ((rem2end / ctx->params->stripe_sectors < ctx->params->chunks_in_zrwa/2)) { // near the last stripe
#ifdef DYN_PP_DIST
        if (ctx->params->chunks_in_zrwa == 1) {
            *pp_distance = -1;
            return 0;
        }
        else
            ctx->params->chunks_in_zrwa /= 2;
#else
        *pp_distance = -1;
        return 0;
#endif
    }
    *pp_distance = (ctx->params->chunks_in_zrwa/2);
    return 1;
}

inline int get_pp_dev_idx(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba, int pp_distance)
{
    int bio_dev_idx, pp_dev_idx;
    bio_dev_idx = lba_to_dev_idx(ctx, (end_lba - 1));
    pp_dev_idx = (bio_dev_idx + 1) % ctx->params->array_width;

    return pp_dev_idx;
}

static inline void __get_pp_location(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba, int pp_distance, int *dev_idx, sector_t *dev_lba)
{
    sector_t su_offset = 0, pzone_start;
    int bio_dev_idx;
    (*dev_idx) = get_pp_dev_idx(ctx, start_lba, end_lba, pp_distance); 

    pzone_start = ctx->devs[*dev_idx].zones[lba_to_lzone(ctx, start_lba)].start;

    (*dev_lba) = pzone_start + ((lba_to_stripe(ctx, end_lba - 1) + pp_distance) << ctx->params->su_shift);
    if (check_same_su(ctx, start_lba, end_lba - 1)) // req is not spanning over chunks
        su_offset = lba_to_su_offset(ctx, start_lba);
    else // req is spanning more or equal than 2 chunks, offset starts from the start sector of the last spanned chunk
        su_offset = 0;
    (*dev_lba) += su_offset;
}

// gap between start_lba & end_lba should be smaller or equal than a chunk
// return: 1 if PP can be written in same lzone (common case), idx & lba is passed through arguments
// return: 0 if PP should be redirected to reserved zone (the last stripe)
raizn_pp_location_t get_pp_location(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba, int *dev_idx, sector_t *dev_lba)
{
    int pp_distance;

    if (!get_pp_distance(ctx, end_lba, &pp_distance))
        return RAIZN_PP_REDIRECT;
    __get_pp_location(ctx, start_lba, end_lba, pp_distance, dev_idx, dev_lba);
    return RAIZN_PP_NORMAL;
}

int raizn_assign_pp_bio(struct raizn_stripe_head *sh, struct raizn_sub_io *ppio, int dev_idx, sector_t dev_lba, void *data, size_t len)
{
	struct page *p;
	struct bio *ppbio = ppio->bio;

#if defined (DUMMY_HDR) && defined (PP_INPLACE)
    p = is_vmalloc_addr(&ppio->header) ? vmalloc_to_page(&ppio->header) :
                        virt_to_page(&ppio->header);
	if (bio_add_page(ppbio, p, PAGE_SIZE, offset_in_page(&ppio->header)) !=
	    PAGE_SIZE) {
		pr_err("Failed to add dummy header page\n");
		bio_endio(ppbio);
		return NULL;
	}
	ppbio->bi_iter.bi_sector = dev_lba - PAGE_SIZE / SECTOR_SIZE;
#else
	ppbio->bi_iter.bi_sector = dev_lba;
#endif

    ppio->dev = &sh->ctx->devs[dev_idx];
    ppio->zone = &sh->ctx->devs[dev_idx].zones[pba_to_pzone(sh->ctx, dev_lba)];
    ppbio->bi_opf = sh->orig_bio->bi_opf;
	p = is_vmalloc_addr(data) ? vmalloc_to_page(data) :
					virt_to_page(data);
    bio_set_op_attrs(ppbio, REQ_OP_WRITE, 0);
	bio_set_dev(ppbio, sh->ctx->devs[dev_idx].dev->bdev);

	if (bio_add_page(ppbio, p, len, 0) != len) {
		printk("Failed to add pp data page\n");
		bio_endio(ppbio);
		return 0;
	}
	return 1;
}

struct raizn_sub_io *raizn_alloc_pp(struct raizn_stripe_head *sh, struct raizn_dev *dev)
{
	struct raizn_ctx *ctx = sh->ctx;
	struct raizn_sub_io *ppio = raizn_stripe_head_alloc_bio(
		sh, &dev->bioset, 1, RAIZN_SUBIO_PP_INPLACE, NULL);
	return ppio;
}

// gap between start_lba & end_lba should be smaller or equal than a chunk
int __raizn_write_pp(struct raizn_stripe_head *sh, sector_t start_lba, sector_t end_lba, void *data)
{
    struct raizn_ctx *ctx = sh->ctx;
    size_t len = end_lba - start_lba;

	raizn_pp_location_t ret;
	struct raizn_dev *dev;
	struct raizn_sub_io *ppio;
	int dev_idx, i;
	sector_t dev_lba;

	ret = get_pp_location(ctx, start_lba, end_lba, &dev_idx, &dev_lba);

	switch (ret)
	{
	case RAIZN_PP_NORMAL:
#ifdef RECORD_PP_AMOUNT
        atomic64_add(len, &ctx->pp_volatile);
#endif
		dev = &ctx->devs[dev_idx];
		ppio = raizn_alloc_pp(sh, dev);
		if (!raizn_assign_pp_bio(sh, ppio, dev_idx, dev_lba, data, len << SECTOR_SHIFT)) {
			pr_err("Fatal: Failed to assign pp bio\n");
			return 0;
		}
		return 1;

	case RAIZN_PP_REDIRECT:
		start_lba = sh->orig_bio->bi_iter.bi_sector;
		raizn_write_md(
			sh,
			lba_to_lzone(ctx, start_lba),
			lba_to_parity_dev(ctx, start_lba),
			RAIZN_ZONE_MD_GENERAL,
            RAIZN_SUBIO_PP_OUTPLACE,
			data, 
            len << SECTOR_SHIFT);
		return 1;

	default:
		printk("ERROR! not defined return from get_pp_location\n");
		break;
	}
	
	return 0;
}

int raizn_write_pp(struct raizn_stripe_head *sh, int parity_su)
{
	struct raizn_ctx *ctx = sh->ctx;
	uint8_t *parity_buf = sh->parity_bufs;

	sector_t start_lba = sh->orig_bio->bi_iter.bi_sector;
	sector_t end_lba = bio_end_sector(sh->orig_bio);
    sector_t start_su = lba_to_su(ctx, start_lba);
    sector_t end_su = lba_to_su(ctx, end_lba - 1);
    sector_t zone_start = sh->zone->start;
    sector_t last_stripe_start = zone_start + (lba_to_stripe(ctx, end_lba - 1) << ctx->params->stripe_shift);
    sector_t end_su_start = (lba_to_su_offset(ctx, end_lba)) ?
        end_lba - lba_to_su_offset(ctx, end_lba) : 
        end_lba - ctx->params->su_sectors;
    int end_chunk_seq = get_dev_sequence_by_lba(ctx, end_lba - 1);
    int prewrtn = 0;

    if (start_su == end_su) {  // non-spanning request. easy to handle
        if (!check_last_su(ctx, end_lba - 1)) { // for the last-seq chunk, FP will be directly written
            calc_parity(ctx, last_stripe_start, parity_buf, end_chunk_seq + 1);
            __raizn_write_pp(sh, start_lba, end_lba, 
                parity_buf + (lba_to_su_offset(ctx, start_lba) << SECTOR_SHIFT));
        }
    }
    else { // spanning request. 0 ~ 2 PP requests are needed.
        if (lba_to_su_offset(ctx, end_lba)) { // chunk-unaligned
            //     //  ------  ------  ------  ------  ------ 
            //     // |      ||      ||      ||  @   ||parity|    (end stripe in bio)
            //     //  ------  ------  ------  ------  ------      
            //                                  @: end lba
            // Partial chunk (final chunk of the bio)
            if (!check_last_su(ctx, end_lba - 1)) { 
                calc_parity(ctx, last_stripe_start, parity_buf, end_chunk_seq + 1);
                __raizn_write_pp(sh, end_su_start, end_lba, 
                    parity_buf);
                prewrtn = 1;
            }
            // Else, the last chunk in the stripe is partial. The last partial write will be protected by FP

            // Write full-chunk PP for previous of the final(partial) chunk. 
            if (!check_last_su(ctx, end_su_start - 1)) {
                sector_t pp_start_offset = 0;
                if (end_su - start_su > 1)
                    pp_start_offset = end_su_start - ctx->params->su_sectors;
                else 
                    pp_start_offset = start_lba;
                    
                calc_parity(ctx, last_stripe_start, parity_buf + prewrtn * (ctx->params->su_sectors << SECTOR_SHIFT), end_chunk_seq);
                __raizn_write_pp(sh, pp_start_offset, end_su_start, 
                    parity_buf + ((prewrtn * ctx->params->su_sectors + lba_to_su_offset(ctx, pp_start_offset)) << SECTOR_SHIFT));
            }
        }
        else { // chunk-aligned: single chunk PP corresponding to the end chunk
            if (!check_last_su(ctx, end_lba - 1)) { // for the last-seq chunk, FP will be directly written
            //     //  ------  ------  ------  ------  ------ 
            //     // |      ||      ||     @||      ||parity|    (end stripe in bio)
            //     //  ------  ------  ------  ------  ------      
            //                                  @: end lba
                calc_parity(ctx, last_stripe_start, parity_buf, end_chunk_seq + 1);
                __raizn_write_pp(sh, end_su_start, end_su_start + ctx->params->su_sectors,
                    parity_buf);
            }
        }
    }
	return 0;
}
