pub mod restart_policy;
pub mod secrets;

use crate::plugins::ValerisPlugin;

pub fn get_common_plugins() -> Vec<Box<dyn ValerisPlugin>> {
    vec![
        Box::new(restart_policy::RestartPolicyPlugin),
        Box::new(secrets::SecretsPlugin),
    ]
}
