use crate::{generic::GenericResponse, routes};
use rocket::{
    Request, catch, catchers,
    fs::{NamedFile, relative},
    get,
    response::Redirect,
    serde::json::Json,
    shield::{Hsts, Shield},
    time::Duration,
    uri,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[rocket::get("/<path..>")]
pub async fn static_pages(path: PathBuf) -> Option<NamedFile> {
    let mut path = Path::new(relative!("static")).join(path);
    if path.is_dir() {
        path.push("index.html");
    }
    NamedFile::open(path).await.ok()
}

#[derive(Serialize)]
pub struct VersionInfo {
    version: String,
}

#[rocket::get("/version")]
pub fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

pub async fn start_web() {
    if let Err(e) = rocket::build()
        .mount(
            "/",
            rocket::routes![
                root_redirect,
                static_pages,
                version,
                routes::openapi::openapi_route,
                routes::openapi::rapidoc,
                // Auth
                routes::token::token_json,
                routes::token::token_form,
                routes::check_token::check_token,
                // Users
                routes::users::get_user,
                routes::users::register,
                routes::users::change_password,
                routes::users::get_users,
                routes::users::update_user,
                routes::users::delete_user,
                routes::bootstrap_admin::bootstrap_admin_route,
            ],
        )
        .register(
            "/",
            catchers![internal_error, not_found, unprocessable_entity, bad_request],
        )
        .attach(Shield::default().enable(Hsts::IncludeSubDomains(Duration::new(31536000, 0))))
        .launch()
        .await
    {
        log::error!("Error starting web server: {e}");
    }
}

#[get("/")]
fn root_redirect() -> Redirect {
    Redirect::to(uri!("/v1/rapidoc"))
}

#[catch(500)]
fn internal_error(_req: &Request<'_>) -> Json<GenericResponse> {
    Json(GenericResponse::error("Internal server error"))
}

#[catch(404)]
fn not_found(_req: &Request<'_>) -> Json<GenericResponse> {
    Json(GenericResponse::error("Endpoint not found"))
}

#[catch(422)]
fn unprocessable_entity(_req: &Request<'_>) -> Json<GenericResponse> {
    Json(GenericResponse::error(
        "The request was well-formed but was unable to be followed due to semantic errors.",
    ))
}

#[catch(400)]
fn bad_request(_req: &Request<'_>) -> Json<GenericResponse> {
    Json(GenericResponse::error(
        "The request could not be understood by the server due to malformed syntax.",
    ))
}
