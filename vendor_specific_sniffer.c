/* Copyright (c) 2020 Wi-Fi Alliance                                                */

/* Permission to use, copy, modify, and/or distribute this software for any         */
/* purpose with or without fee is hereby granted, provided that the above           */
/* copyright notice and this permission notice appear in all copies.                */

/* THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL                    */
/* WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                    */
/* WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL                     */
/* THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                       */
/* CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING                        */
/* FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF                       */
/* CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT                       */
/* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS                          */
/* SOFTWARE. */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "vendor_specific.h"
#include "utils.h"

#ifdef _TEST_SNIFFER_
/**
 * Generic platform dependent API implementation 
 */

void interfaces_init() {
    char buffer[BUFFER_LEN];

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw phy phy0 interface add mon0 type monitor >/dev/null 2>/dev/null");
    system(buffer);

    sleep(1);
}

/* Be invoked when start controlApp */
void vendor_init() {
    interfaces_init();
}

/* Be invoked when terminate controlApp */
void vendor_deinit() {
    char buffer[S_BUFFER_LEN];
    memset(buffer, 0, sizeof(buffer));
    system("iw dev mon0 del >/dev/null 2>/dev/null");
}

#endif /* _TEST_SNIFFER_ */
