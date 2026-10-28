pub mod credentials;
pub mod extensions;
pub mod gitconfig;
pub mod launchagents;
pub mod osv;
pub mod php;
pub mod shell;
pub mod ssh;

pub use credentials::{scan_credentials, scan_credentials_with_home, CREDENTIALS_SUB_CATEGORY};
pub use extensions::{
    scan_extensions, scan_extensions_with_home, EXT_SUB_CATEGORY, MALWARE_FILES_SUB_CATEGORY,
};
pub use gitconfig::{scan_git_config, scan_git_config_with, GIT_CONFIG_SUB_CATEGORY};
pub use launchagents::{
    scan_launch_agents, scan_launch_agents_with_home, LAUNCH_AGENTS_SUB_CATEGORY,
};
pub use osv::{scan_osv, scan_osv_with, OsvTransport, Package, OSV_SUB_CATEGORY};
pub use php::{scan_php_runtimes, scan_php_runtimes_with_roots, PHP_SUB_CATEGORY};
pub use shell::{
    scan_shell, scan_shell_with_home, SHELL_HISTORY_SUB_CATEGORY, SHELL_STARTUP_SUB_CATEGORY,
};
pub use ssh::{
    inspect_authorized_keys_content, inspect_ssh_config_content, inspect_ssh_key_content, scan_ssh,
    scan_ssh_with_home, SSH_SUB_CATEGORY,
};
