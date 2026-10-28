pub mod autoapprove;
pub mod claude;
pub mod mcp;
pub mod plugins;
pub mod rules_unicode;
pub mod tasks_secrets;

pub use autoapprove::{
    scan_agent_autoapprove, scan_agent_autoapprove_with, AUTOAPPROVE_SUB_CATEGORY,
};
pub use claude::{
    inspect_claude_content, inspect_claude_file, scan_claude_settings,
    scan_claude_settings_with_home,
};
pub use mcp::{
    inspect_mcp_content, inspect_mcp_file, scan_mcp_servers, scan_mcp_servers_with_home,
};
pub use plugins::{scan_claude_plugins, scan_claude_plugins_with_home, PLUGINS_SUB_CATEGORY};
pub use rules_unicode::{scan_rules_unicode, scan_rules_unicode_with, RULES_UNICODE_SUB_CATEGORY};
pub use tasks_secrets::{
    inspect_env_content, inspect_env_file, inspect_tasks_content, inspect_tasks_file,
    scan_plaintext_keys, scan_plaintext_keys_with_home, scan_vscode_tasks,
    scan_vscode_tasks_with_home,
};
