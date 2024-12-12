#ifndef __IOSUB_H__
#define __IOSUB_H__

#include "zraid.h"

int raizn_read(struct raizn_stripe_head *sh);
struct raizn_sub_io *raizn_alloc_md(struct raizn_stripe_head *sh,
					   sector_t lzoneno,
					   struct raizn_dev *dev,
					   raizn_zone_type mdtype, 
					   sub_io_type_t subio_type,
					   void *data,
					   size_t len);

int raizn_write_md(struct raizn_stripe_head *sh, sector_t lzoneno,
			  struct raizn_dev *dev, raizn_zone_type mdtype,
	   		  sub_io_type_t subio_type,
			  void *data, size_t len);

int raizn_write(struct raizn_stripe_head *sh);
int raizn_flush(struct raizn_stripe_head *sh);
int raizn_zone_open(struct raizn_stripe_head *sh);
int raizn_zone_close(struct raizn_stripe_head *sh);
int raizn_zone_finish(struct raizn_stripe_head *sh);
int raizn_zone_append(struct raizn_stripe_head *sh);
int raizn_zone_reset_bottom(struct raizn_stripe_head *sh);
int raizn_zone_reset_top(struct raizn_stripe_head *sh);
int raizn_zone_reset_all(struct raizn_stripe_head *sh);
void raizn_handle_io_mt(struct work_struct *work);

#endif