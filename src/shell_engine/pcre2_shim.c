/* Thin C helpers around PCRE2 for Zig shell_engine pack matching. */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pcre2_code *code;
    /* Reused across matches. Hook evaluation is single-threaded per process. */
    pcre2_match_data *md;
} ryk_regex;

ryk_regex *ryk_regex_compile(const char *pattern, size_t len, int *err_code, size_t *err_offset) {
    int ec = 0;
    PCRE2_SIZE eo = 0;
    /* DOTALL so `.` matches newlines (heredoc bodies). UTF off (byte patterns). */
    uint32_t options = PCRE2_DOTALL;
    pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern, (PCRE2_SIZE)len, options, &ec, &eo, NULL);
    if (!code) {
        if (err_code) *err_code = ec;
        if (err_offset) *err_offset = (size_t)eo;
        return NULL;
    }
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(code, NULL);
    if (!md) {
        pcre2_code_free(code);
        return NULL;
    }
    ryk_regex *re = (ryk_regex *)malloc(sizeof(ryk_regex));
    if (!re) {
        pcre2_match_data_free(md);
        pcre2_code_free(code);
        return NULL;
    }
    re->code = code;
    re->md = md;
    return re;
}

void ryk_regex_free(ryk_regex *re) {
    if (!re) return;
    if (re->md) pcre2_match_data_free(re->md);
    pcre2_code_free(re->code);
    free(re);
}

int ryk_regex_match_span(
    ryk_regex *re,
    const char *text,
    size_t len,
    size_t *out_start,
    size_t *out_end) {
    if (!re || !re->code || !re->md) return -1;
    /* Empty subject is valid (no-match or match of empty patterns); never read past len. */
    if (!text && len != 0) return -1;

    pcre2_match_data *md = re->md;

    const PCRE2_SPTR subject = text ? (PCRE2_SPTR)text : (PCRE2_SPTR)"";
    int rc = pcre2_match(re->code, subject, (PCRE2_SIZE)len, 0, 0, md, NULL);
    if (rc >= 0) {
        if (out_start || out_end) {
            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
            if (ovector) {
                if (out_start) *out_start = (size_t)ovector[0];
                if (out_end) *out_end = (size_t)ovector[1];
            }
        }
        return 1;
    }
    if (rc == PCRE2_ERROR_NOMATCH) return 0;
    /* Preserve negative PCRE2 error codes for diagnostics; all mean fail-closed. */
    return rc < 0 ? rc : -3;
}

int ryk_regex_is_match(ryk_regex *re, const char *text, size_t len) {
    return ryk_regex_match_span(re, text, len, NULL, NULL);
}
