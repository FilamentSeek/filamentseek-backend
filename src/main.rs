mod error;
mod generic;
mod jobs;
mod models;
mod routes;
mod web;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .filter_module("tracing::span", log::LevelFilter::Warn)
        .filter_module("serenity", log::LevelFilter::Warn)
        .init();

    let cwd = std::env::current_dir().expect("Failed to get current directory");

    if !cwd.join("Cargo.toml").exists() {
        panic!("Invalid working directory");
    }

    generic::Environment::load_path("config.toml");
    log::info!("Starting...");
    jobs::Job::spawn_all();
    web::start_web().await;
    log::info!("Shutting down...");
}
