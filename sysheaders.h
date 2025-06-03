#ifndef SYSTEM_H

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#ifndef ADJ_SETOFFSET
#define ADJ_SETOFFSET           0x0100  /* add 'time' to current time */
#endif
#ifndef ADJ_MICRO
#define ADJ_MICRO               0x1000  /* select microsecond resolution */
#endif
#ifndef ADJ_NANO
#define ADJ_NANO                0x2000  /* select nanosecond resolution */
#endif
#ifndef ADJ_OFFSET_SS_READ
#define ADJ_OFFSET_SS_READ      0xa001  /* read-only adjtime */
#endif
#ifndef STA_NANO
#define STA_NANO        0x2000  /* resolution (0 = us, 1 = ns) (ro) */
#endif
#ifndef STA_MODE
#define STA_MODE        0x4000  /* mode (0 = PLL, 1 = FLL) (ro) */
#endif
#endif

#endif
