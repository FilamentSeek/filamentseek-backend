use surreal_socket::dbrecord::DBRecord;

use crate::generic::surrealdb_client;

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

    // Check surrealdb connection
    surrealdb_client()
        .await
        .expect("Failed to connect to SurrealDB");

    if std::env::args().any(|arg| arg == "--init") {
        log::info!("Initializing debug products...");
        init_debug_products().await;
        log::info!("Debug products initialized.");
        return;
    }

    log::info!("Starting...");
    jobs::Job::spawn_all();
    web::start_web().await;
    log::info!("Shutting down...");
}

async fn init_debug_products() {
    let client = surrealdb_client()
        .await
        .expect("Failed to connect to SurrealDB");

    let _ = filamentseek_model::product::Product::db_drop_table(&client).await;
    let mut tasks = vec![];

    for i in 0..100 {
        let product = filamentseek_model::product::Product {
            uuid: surreal_socket::dbrecord::SsUuid::new(),
            name: format!("Test Product {}", i + 1),
            price: filamentseek_model::product::Cents(2099),
            price_per_kg: filamentseek_model::product::Cents(0),
            url: "https://example.com".to_string(),
            material: filamentseek_model::product::FilamentMaterial::PLA,
            diameter: filamentseek_model::product::FilamentDiameter::D175,
            weight: filamentseek_model::product::Grams(1000),
            retailer: filamentseek_model::product::Retailer::Amazon,
            retailer_product_id: "TEST123".to_string(),
            color: "Red".to_string(),
        };

        let client = client.clone();

        let handle = tokio::task::spawn(async move {
            if let Err(e) = surreal_socket::dbrecord::DBRecord::db_create(&product, &client).await {
                log::error!("Failed to create product: {:?}", e);
            }
        });

        tasks.push(handle);
    }

    for task in tasks {
        let _ = task.await;
    }
}
