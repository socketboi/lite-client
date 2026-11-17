/* Execute the production metadata decoder on blocks captured by the pinned Framer. */
#include "../../src/reality/fetch.c"
#define LC_HEADER_BUDGET_CASES
#include "header_budget_reference.h"

int main(void)
{
    (void)reference_header_continuation_cutoff;
    for (size_t i = 0; i < sizeof budget_cases / sizeof budget_cases[0]; i++) {
        const struct budget_case *test = &budget_cases[i];
        lc_spider_fetch f = {0};
        fetch_cc cc = {0};
        cc.m.remain = cc.m.trailer_remain = 128;
        cc.dec.max_str = 128;
        int rc = meta_fragment(&f, &cc, test->block, test->len);
        if (rc == 0)
            rc = lc_hpack_close(&cc.dec);
        if ((rc != 0) != test->error || cc.m.truncated != test->truncated) {
            fprintf(stderr, "FAIL budget %s: error %d/%d, truncated %d/%d\n", test->name,
                    rc != 0, test->error, cc.m.truncated, test->truncated);
            return 1;
        }
        lc_hpack_dec_free(&cc.dec);
        meta_reset(&cc.m);
        printf("  ok    pinned header/trailer budget: %s\n", test->name);
    }
    return 0;
}
