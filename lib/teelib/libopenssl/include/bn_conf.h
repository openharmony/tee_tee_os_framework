/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef __TEE_BN_CONF_H
# define __TEE_BN_CONF_H

/* Only one for the following should be defined */
#  if defined(__arm) || defined(__arm__)
#  define THIRTY_TWO_BIT
#  undef SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  elif defined(__aarch64__)
#  undef SIXTY_FOUR_BIT_LONG
#  undef THIRTY_TWO_BIT
#  define SIXTY_FOUR_BIT
#  endif

#endif
