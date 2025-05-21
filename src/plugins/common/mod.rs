pub mod secrets;
pub mod restart_policy;

use crate::plugins::ValerisPlugin;

pub fn get_common_plugins() -> Vec<Box<dyn ValerisPlugin>> {
    vec![
        Box::new(secrets::SecretsPlugin),
        Box::new(restart_policy::RestartPolicyPlugin),
    ]
}
