/* loongarch.h -- check for loongson features.
 *
 * Copyright (c) 2020 Loongson Technology Corporation Limited
 * All rights reserved.
 * Contributed by Song Ding <songding@loongson.cn>
 *
 * For conditions of distribution and use, see copyright notice in gzip.h
 */
#ifndef __LOONGARCH_H_
#define __LOONGARCH_H_

//extern int have_lasx;

extern unsigned int OPENSSL_loongarchcap_P;
#define LOONGARCH_CFG2 0x02
#define LOONGARCH_CFG2_LSX  (1<<6)
#define LOONGARCH_CFG2_LASX (1<<7)
#endif /* __LOONGARCH_H_ */
