use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use rocket::{response::status, serde::json::Json};
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

use crate::{
    error::Error,
    generic::{BearerToken, GenericResponse, surrealdb_client},
};

use filamentseek_model::product::{
    Cents, FilamentDiameter, FilamentMaterial, Grams, Product, ProductRequest, ProductResponse,
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

    let product = Product::db_get_by_id(&client, product_id)
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

    let existing_product = if let Some(product) = Product::db_get_by_id(&client, product_id)
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

    let existing_product = if let Some(product) = Product::db_get_by_id(&client, product_id)
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

const MAX_PER_PAGE: u32 = 100;

/// Search products
#[utoipa::path(
    post,
    path = "/v1/products/search",
    description = "Search products.",
    request_body(content = ProductSearchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "OK", body = ProductSearchResponse)
    ),
    security(),
    tag = "product"
)]
#[rocket::post("/v1/products/search", data = "<request>")]
pub async fn search_products(
    request: Json<ProductSearchRequest>,
) -> Result<Json<ProductSearchResponse>, status::Custom<Json<GenericResponse>>> {
    if request.per_page > MAX_PER_PAGE {
        return Err(
            Error::bad_request(&format!("per_page cannot be greater than {MAX_PER_PAGE}")).into(),
        );
    }

    let client = surrealdb_client().await.map_err(Error::from)?;
    let mut products = Product::db_all(&client).await.map_err(Error::from)?;

    if let Some(sort_by) = &request.sort_by {
        match sort_by {
            SortBy::Price => products.sort_by_key(|p| p.price),
            SortBy::PricePerKg => products.sort_by_key(|p| p.price_per_kg),
        }
    }

    if let Some(min_price) = request.min_price {
        products.retain(|p| p.price >= min_price);
    }
    if let Some(max_price) = request.max_price {
        products.retain(|p| p.price <= max_price);
    }
    if let Some(material) = &request.material {
        products.retain(|p| &p.material == material);
    }
    if let Some(color) = &request.color {
        products.retain(|p| p.color.to_lowercase() == color.to_lowercase());
    }
    if let Some(diameter) = &request.diameter {
        products.retain(|p| &p.diameter == diameter);
    }
    if let Some(weight) = request.weight {
        products.retain(|p| p.weight == weight);
    }

    if let Some(name) = &request.name {
        let matcher = SkimMatcherV2::default();
        let mut ranked: Vec<_> = products
            .into_iter()
            .filter_map(|e| {
                matcher
                    .fuzzy_match(&e.name.to_string(), name)
                    .map(|score| (score, e))
            })
            .collect();
        ranked.sort_by_key(|(score, _)| *score);
        ranked.reverse();
        products = ranked.into_iter().map(|(_, p)| p).collect();
    }

    let page = request.page.unwrap_or(1).max(1);
    let per_page = request.per_page.clamp(1, MAX_PER_PAGE);
    let offset = (page - 1) as usize * per_page as usize;
    let total_len = products.len();
    let end = total_len.min(offset + per_page as usize);

    let page_slice: Vec<ProductResponse> = if offset < total_len {
        products[offset..end]
            .iter()
            .cloned()
            .map(|p| p.into())
            .collect()
    } else {
        Vec::new()
    };

    let resp = ProductSearchResponse {
        items: page_slice,
        total: total_len as u64,
        total_pages: ((total_len as f64) / (per_page as f64)).ceil() as u64,
    };

    Ok(Json(resp))
}

#[derive(Deserialize, ToSchema)]
pub struct ProductSearchRequest {
    pub name: Option<String>,
    pub min_price: Option<Cents>,
    pub max_price: Option<Cents>,
    pub material: Option<FilamentMaterial>,
    pub color: Option<String>,
    pub diameter: Option<FilamentDiameter>,
    pub weight: Option<Grams>,
    pub sort_by: Option<SortBy>,

    pub page: Option<u32>,
    pub per_page: u32,
}

#[derive(Serialize, ToSchema)]
pub struct ProductSearchResponse {
    pub items: Vec<ProductResponse>,
    pub total: u64,
    pub total_pages: u64,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortBy {
    Price,
    PricePerKg,
}
