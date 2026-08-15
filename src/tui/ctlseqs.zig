/// DEC synchronized-output (CSI ? 2026). Same bytes as libvaxis `ctlseqs.sync_*`,
/// kept here so the linear banner/spinner path never `@import("vaxis")`.
pub const sync_set = "\x1b[?2026h";
pub const sync_reset = "\x1b[?2026l";
