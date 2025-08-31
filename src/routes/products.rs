use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use rocket::{response::status, serde::json::Json};
use serde::Deserialize;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

use crate::{
    error::Error,
    generic::{BearerToken, GenericResponse, surrealdb_client},
    models::product::{Product, ProductRequest, ProductResponse},
};

/// Get product
#[utoipa::path(
    get,
    path = "/v1/products/{product_id}",
    description = "Fetch a single product by its ID.",
    params(
        ("product_id" = String, Path, description = "Product ID")
    ),
    request_body(content = ProductRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Product fetched", body = ProductResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse),
    ),
    security(),
    tag = "product"
)]
#[rocket::get("/v1/products/<product_id>")]
pub async fn get_product(
    product_id: &str,
) -> Result<Json<ProductResponse>, status::Custom<Json<GenericResponse>>> {
    let client = surrealdb_client().await.map_err(Error::from)?;

    let product = Product::db_by_id(&client, product_id)
        .await
        .map_err(Error::from)?;

    if let Some(product) = product {
        Ok(Json(product.into()))
    } else {
        Err(Error::not_found(&format!("Product with ID `{product_id}` not found")).into())
    }
}

/// Create product
#[utoipa::path(
    post,
    path = "/v1/products",
    description = "Create a new product. Admins only.",
    request_body(content = ProductRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Product created", body = ProductResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse),
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "product"
)]
#[rocket::post("/v1/products", data = "<request>")]
pub async fn create_product(
    request: Json<ProductRequest>,
    bearer_token: BearerToken,
) -> Result<Json<ProductResponse>, status::Custom<Json<GenericResponse>>> {
    let user = bearer_token.validate().await?.user().await?;

    if !user.is_admin {
        return Err(Error::forbidden().into());
    }

    let product: Product = request.into_inner().into();
    let client = surrealdb_client().await.map_err(Error::from)?;
    product.db_create(&client).await.map_err(Error::from)?;
    Ok(Json(product.into()))
}

/// Update product
#[utoipa::path(
    post,
    path = "/v1/products/{product_id}",
    description = "Update an existing product. Admins only.",
    params(
        ("product_id" = String, Path, description = "Existing product ID")
    ),
    request_body(content = ProductRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Product updated", body = ProductResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse),
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "product"
)]
#[rocket::post("/v1/products/<product_id>", data = "<request>")]
pub async fn update_product(
    request: Json<ProductRequest>,
    bearer_token: BearerToken,
    product_id: &str,
) -> Result<Json<ProductResponse>, status::Custom<Json<GenericResponse>>> {
    let user = bearer_token.validate().await?.user().await?;

    if !user.is_admin {
        return Err(Error::forbidden().into());
    }

    let client = surrealdb_client().await.map_err(Error::from)?;

    let existing_product = if let Some(product) = Product::db_by_id(&client, product_id)
        .await
        .map_err(Error::from)?
    {
        product
    } else {
        return Err(
            Error::bad_request(&format!("Product with ID `{product_id}` does not exist")).into(),
        );
    };

    let mut request_product: Product = request.into_inner().into();
    request_product.uuid = existing_product.uuid.to_owned();

    request_product
        .db_overwrite(&client)
        .await
        .map_err(Error::from)?;

    Ok(Json(request_product.into()))
}

/// Delete product
#[utoipa::path(
    delete,
    path = "/v1/products/{product_id}",
    description = "Delete a product. Admins only.",
    params(
        ("product_id" = String, Path, description = "Existing product ID")
    ),
    responses(
        (status = 200, description = "Product deleted", body = ProductResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse),
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "product"
)]
#[rocket::delete("/v1/products/<product_id>")]
pub async fn delete_product(
    bearer_token: BearerToken,
    product_id: &str,
) -> Result<Json<ProductResponse>, status::Custom<Json<GenericResponse>>> {
    let user = bearer_token.validate().await?.user().await?;

    if !user.is_admin {
        return Err(Error::forbidden().into());
    }

    let client = surrealdb_client().await.map_err(Error::from)?;

    let existing_product = if let Some(product) = Product::db_by_id(&client, product_id)
        .await
        .map_err(Error::from)?
    {
        product
    } else {
        return Err(
            Error::bad_request(&format!("Product with ID `{product_id}` does not exist")).into(),
        );
    };

    existing_product
        .db_delete(&client)
        .await
        .map_err(Error::from)?;

    Ok(Json(existing_product.into()))
}

/// Search products
#[utoipa::path(
    post,
    path = "/v1/products/search",
    description = "Search products.",
    request_body(content = ProductSearchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "OK", body = Vec<ProductResponse>),
    ),
    security(),
    tag = "product"
)]
#[rocket::post("/v1/products/search", data = "<request>")]
pub async fn search_products(
    request: Json<ProductSearchRequest>,
) -> Result<Json<Vec<ProductResponse>>, status::Custom<Json<GenericResponse>>> {
    let client = surrealdb_client().await.map_err(Error::from)?;

    if let Some(name) = &request.name {
        let matcher = SkimMatcherV2::default();
        let all_products = Product::db_all(&client).await.map_err(Error::from)?;

        let mut result_products: Vec<_> = all_products
            .into_iter()
            .filter_map(|e| {
                matcher
                    .fuzzy_match(&e.name.to_string(), name)
                    .map(|score| (score, e))
            })
            .collect();

        result_products.sort_by_key(|(score, _)| *score);
        result_products.reverse();

        let results: Vec<ProductResponse> =
            result_products.into_iter().map(|(_, e)| e.into()).collect();

        return Ok(Json(results));
    }

    // temp: return all (todo: other filters)
    let all_products = Product::db_all(&client).await.map_err(Error::from)?;
    let results: Vec<ProductResponse> = all_products.into_iter().map(|e| e.into()).collect();
    Ok(Json(results))
}

#[derive(Deserialize, ToSchema)]
pub struct ProductSearchRequest {
    name: Option<String>,
    // etc
}
