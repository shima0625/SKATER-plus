#pragma once
/* Returns 1 after replacement (caller must exit), 0 otherwise. */
int updater_check(const char *launch_path);
const char *updater_status(void);
