#ifndef __UTIL_H__
#define __UTIL_H__

void print_buf_hex(void *buf);

static void raizn_record_op(struct raizn_stripe_head *sh);
inline struct raizn_dev *get_bio_dev(struct raizn_ctx *ctx, struct bio *bio);
inline int get_bio_dev_idx(struct raizn_ctx *ctx, struct bio *bio);
inline int get_dev_sequence(struct raizn_ctx *ctx, int dev_idx, int parity_idx);
inline int get_dev_sequence_by_pba(struct raizn_ctx *ctx, int devno, sector_t pba);
inline int get_dev_sequence_by_lba(struct raizn_ctx *ctx, sector_t lba);

inline sector_t lba_to_stripe(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_su(struct raizn_ctx *ctx, sector_t lba);
inline bool check_same_su(struct raizn_ctx *ctx, sector_t lba1, sector_t lba2);
inline bool check_last_su(struct raizn_ctx *ctx, sector_t lba);
inline sector_t pba_to_pzone(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_lzone(struct raizn_ctx *ctx, sector_t lba);
inline int lba_to_parity_dev_idx(struct raizn_ctx *ctx, sector_t lba);
struct raizn_dev *lba_to_parity_dev(struct raizn_ctx *ctx, sector_t lba);
struct raizn_dev *lba_to_dev(struct raizn_ctx *ctx, sector_t lba);
inline int lba_to_dev_idx(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_lzone_offset(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_stripe_offset(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_su_offset(struct raizn_ctx *ctx, sector_t lba);
inline sector_t bytes_to_stripe_offset(struct raizn_ctx *ctx, uint64_t ptr);
inline sector_t lba_to_stripe_addr(struct raizn_ctx *ctx, sector_t lba);
inline sector_t lba_to_pba_default(struct raizn_ctx *ctx, sector_t lba);
inline int raizn_submit_bio(struct raizn_ctx *ctx, char *funcname, struct bio *bio, bool wait);
#ifdef SMALL_ZONE_AGGR
inline sector_t pba_to_aggr_addr(struct raizn_ctx *ctx, sector_t pba);
inline int raizn_submit_bio_aggr(struct raizn_ctx *ctx, char *funcname, struct bio *bio, struct raizn_dev *dev, bool wait);
#endif
inline sector_t block_to_sector_addr(sector_t block_addr);
inline sector_t sector_to_block_addr(sector_t sector_addr);
inline void raizn_record_subio(struct raizn_stripe_head *sh, struct raizn_sub_io *subio);
// inline void raizn_record_subio(struct raizn_sub_io *subio);
void raizn_print_subio_counter(struct raizn_ctx *ctx);
void raizn_print_zf_counter(struct raizn_ctx *ctx);
inline bool subio_ready2submit(struct raizn_sub_io *subio, bool data);
inline void reset_stripe_buf(struct raizn_ctx *ctx, sector_t start, sector_t end);
void calc_parity(struct raizn_ctx *ctx, sector_t start_lba, void *dst, int num_xor_units);
void print_bio_info(struct raizn_ctx *ctx, struct bio *bio, char *funcname);

void raizn_stripe_head_hold_completion(struct raizn_stripe_head *sh);
void raizn_stripe_head_release_completion(struct raizn_stripe_head *sh);
struct raizn_sub_io *
raizn_stripe_head_alloc_subio(struct raizn_stripe_head *sh,
			      sub_io_type_t sub_io_type);
struct raizn_sub_io *
raizn_stripe_head_add_bio(struct raizn_stripe_head *sh, struct bio *bio,
			  sub_io_type_t sub_io_type);
struct raizn_sub_io *
raizn_stripe_head_alloc_bio(struct raizn_stripe_head *sh,
			    struct bio_set *bioset, int bvecs,
			    sub_io_type_t sub_io_type, void *data);

struct raizn_stripe_head *
raizn_stripe_head_alloc(struct raizn_ctx *ctx, struct bio *bio, raizn_op_t op);
void raizn_stripe_head_free(struct raizn_stripe_head *sh);
size_t raizn_stripe_buffer_parity(struct raizn_ctx *ctx,
					 sector_t start_lba, void *dst);
int raizn_bio_parity(struct raizn_ctx *ctx, struct bio *src, void *dst);
int buffer_stripe_data(struct raizn_stripe_head *sh, sector_t start,
			      sector_t end);

#endif //ifdef __UTIL_H__
