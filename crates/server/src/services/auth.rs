use std::collections::HashMap;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const RELATIVE_DATA_PATH: &str = "data";
const USER_FILE: &str = "users.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub password: String,
}

fn get_user_file_path() -> PathBuf {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = project_root.join(RELATIVE_DATA_PATH);

    if !data_dir.exists() {
        eprintln!("Data directory does not exist, creating: {:?}", data_dir);
        create_dir_all(&data_dir).expect("Failed to create data directory");
    }

    data_dir.join(USER_FILE)
}

#[derive(Serialize, Deserialize)]
pub struct Users(pub HashMap<String, String>);

fn load_users() -> Result<HashMap<String, String>, String> {
    let path = get_user_file_path();

    if !path.exists() {
        save_users(&HashMap::new());
        return Err("User file not found, created a new one.".into());
    }

    Ok(read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default())
}

fn save_users(users: &HashMap<String, String>) {
    let json = serde_json::to_string_pretty(users).unwrap();
    let path = get_user_file_path();
    write(path, json).expect("failed to write user file");
}

pub fn register(email: &str, password: &str) -> Result<(), String> {
    let mut users = load_users().unwrap();
    if users.contains_key(email) {
        return Err("User already exists".into());
    }
    users.insert(email.to_string(), password.to_string());
    save_users(&users);
    Ok(())
}

pub fn login(email: &str, password: &str) -> Result<String, String> {
    let users = load_users().unwrap();
    match users.get(email) {
        Some(stored) if stored == password => Ok(email.to_string()),
        _ => Err("Invalid credentials".into()),
    }
}
