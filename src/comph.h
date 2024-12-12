#ifndef __COMPH_H__
#define __COMPH_H__


void comph_endio(struct bio *bio);
void raizn_reset_prog_bitmap_zone(struct raizn_ctx *ctx, struct raizn_zone *lzone);
int comph_open_zone_init(struct raizn_ctx *ctx, int zoneno);
sector_t get_wp_pba(struct raizn_ctx *ctx, sector_t end_lba, int pp_distance, int wp_entry_idx);
void generate_wp_log(struct raizn_stripe_head *sh, struct raizn_sub_io *wlio, sector_t end_lba);

struct __attribute__((__packed__)) wp_log_entry 
{
    uint64_t magic;
    uint64_t timestamp;
    sector_t lba;
	char padding[DEV_BLOCKSIZE - sizeof(uint64_t) - sizeof(uint64_t) - sizeof(sector_t)];
};

#endif