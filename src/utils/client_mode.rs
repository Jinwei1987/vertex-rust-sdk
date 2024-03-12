use crate::utils::deployment::Deployment;
use include_dir::{include_dir, Dir};
use std::fs;
use std::path::Path;

static CONFIGS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/vertex_utils/configs");
#[derive(Clone, PartialEq)]
pub enum ClientMode {
    Prod,
    BlastProd,
    SepoliaTest,
    BlastTest,
    Local,
    LocalAlt,
}

impl ClientMode {
    pub fn default_gateway_url(&self) -> String {
        let envtag = self.vertex_envtag();
        match self {
            Self::Local | Self::LocalAlt => {
                format!("http://gateway.{envtag}.vertexprotocol.com:80/v1")
            }
            _ => {
                format!("https://gateway.{envtag}.vertexprotocol.com/v1")
            }
        }
    }

    pub fn default_trigger_url(&self) -> String {
        let envtag = self.vertex_envtag();
        match self {
            Self::Local | Self::LocalAlt => {
                format!("http://trigger.{envtag}.vertexprotocol.com:8080/v1")
            }
            _ => {
                format!("https://trigger.{envtag}.vertexprotocol.com/v1")
            }
        }
    }

    pub fn default_archive_url(&self) -> String {
        let envtag = self.vertex_envtag();
        match self {
            Self::Local | Self::LocalAlt => {
                format!("http://archive.{envtag}.vertexprotocol.com:8000/v1")
            }
            _ => {
                format!("https://archive.{envtag}.vertexprotocol.com/v1")
            }
        }
    }

    pub fn vertex_envtag(&self) -> String {
        match self {
            Self::Local => "local",
            Self::LocalAlt => "local-alt",
            Self::SepoliaTest => "sepolia-test",
            Self::BlastTest => "blast-test",
            Self::Prod => "prod",
            Self::BlastProd => "blast-prod",
        }
        .to_string()
    }

    pub fn deployment(&self) -> Deployment {
        let network = self.vertex_envtag();
        let deployment_path = Path::new(&network).join("deployment.json");

        // Order of loading
        // 1. try ENVVAR override
        // 2. try locally configured directory
        // 3. use deployment.json included in binary
        let deployment_str = match std::env::var("VERTEX_CONFIGS_DIR") {
            Ok(path) => {
                let deployment_path = Path::new(&path).join(&network).join("deployment.json");
                fs::read_to_string(&deployment_path).expect(&format!(
                    "Failed to read {}",
                    &deployment_path.to_string_lossy()
                ))
            }
            Err(_) => {
                let package_dir = env!("CARGO_MANIFEST_DIR");
                let default_configs_path = Path::new(package_dir)
                    .join("src/vertex_utils/configs")
                    .join(&network)
                    .join("deployment.json");

                fs::read_to_string(&default_configs_path).unwrap_or_else(|_| {
                    CONFIGS
                        .get_file(deployment_path.to_str().unwrap())
                        .expect("Deployment file not found")
                        .contents_utf8()
                        .expect("Failed to read deployment file")
                        .to_string()
                })
            }
        };

        serde_json::from_str(&deployment_str).unwrap()
    }
}
