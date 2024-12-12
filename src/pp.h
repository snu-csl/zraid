#ifndef __PP_H__
#define __PP_H__
#include "zraid.h"

typedef enum {
    RAIZN_PP_NONEED, // PP is not needed (full stripe)
    RAIZN_PP_NORMAL, // PP in the same lzone
    RAIZN_PP_REDIRECT // PP should be redirected to reserved zone
} raizn_pp_location_t;

raizn_pp_location_t get_pp_location(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba, int *dev_idx, sector_t *dev_lba);
inline int get_pp_dev_idx(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba, int pp_distance);
int raizn_assign_pp_bio(struct raizn_stripe_head *sh, struct raizn_sub_io *ppio, int dev_idx, sector_t dev_lba, void *data, size_t len);
struct raizn_sub_io *raizn_alloc_pp(struct raizn_stripe_head *sh, struct raizn_dev *dev);
int __raizn_write_pp(struct raizn_stripe_head *sh, sector_t start_lba, sector_t end_lba, void *data);
int raizn_write_pp(struct raizn_stripe_head *sh, int parity_su);
void raizn_pp_manage(struct raizn_ctx *ctx, sector_t start_lba, sector_t end_lba);
void print_bitmap(struct raizn_ctx *ctx, struct raizn_zone *lzone);
void raizn_do_zrwa_flush(struct raizn_stripe_head *sh, sector_t start_lba, sector_t end_lba);
int raizn_write_wp_log(struct raizn_stripe_head *sh, sector_t end_lba);
inline int get_pp_distance(struct raizn_ctx *ctx, sector_t end_lba, int *pp_distance);

#endif //ifdef __PP_H__
