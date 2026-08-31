#ifndef SETTINGS_PATCH_HOOK_H
#define SETTINGS_PATCH_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

int settings_patch_hook_install(void);

int settings_patch_hook_uninstall(void);

int settings_patch_hook_is_installed(void);

#ifdef __cplusplus
}
#endif

#endif /* SETTINGS_PATCH_HOOK_H */
