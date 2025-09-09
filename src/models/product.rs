use std::str::FromStr;

use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::{
    dbrecord::{DBRecord, SsUuid},
    error::SurrealSocketError,
};
use utoipa::ToSchema;

use crate::generic::surrealdb_client;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Product {
    pub uuid: SsUuid<Product>,
    pub name: String,
    pub price: Cents,
    pub price_per_kg: Cents,
    pub url: String,
    pub material: FilamentMaterial,
    pub diameter: FilamentDiameter,
    pub weight: Grams,
    pub retailer: Retailer,
    pub retailer_product_id: String,
    pub color: String,
}

#[async_trait]
impl DBRecord for Product {
    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }

    const TABLE_NAME: &'static str = "products";

    async fn post_update_hook(&self) -> Result<(), SurrealSocketError> {
        let price_per_kg = ((self.price.0 as f32 / self.weight.0 as f32) * 1000.0).round() as u32;
        let client = surrealdb_client().await?;

        let query = format!(
            r#"
            UPDATE {} SET price_per_kg = {} WHERE {} = {};
            "#,
            Self::table(),
            price_per_kg,
            Self::UUID_FIELD,
            serde_json::to_string(&self.uuid())?
        );

        client.query(&query).await?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Cents(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum FilamentMaterial {
    PLA,
    PLAPlus,
    ABS,
    PETG,
    TPU,
    Nylon,
    PC,
    ASA,
    Unspecified,
    Other(String),
}

impl FromStr for FilamentMaterial {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "PLA" => Self::PLA,
            "PLAPlus" => Self::PLAPlus,
            "ABS" => Self::ABS,
            "PETG" => Self::PETG,
            "TPU" => Self::TPU,
            "Nylon" => Self::Nylon,
            "PC" => Self::PC,
            "ASA" => Self::ASA,
            "Unspecified" => Self::Unspecified,
            other => Self::Other(other.to_string()),
        })
    }
}

impl std::fmt::Display for FilamentMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PLA => write!(f, "PLA"),
            Self::PLAPlus => write!(f, "PLAPlus"),
            Self::ABS => write!(f, "ABS"),
            Self::PETG => write!(f, "PETG"),
            Self::TPU => write!(f, "TPU"),
            Self::Nylon => write!(f, "Nylon"),
            Self::PC => write!(f, "PC"),
            Self::ASA => write!(f, "ASA"),
            Self::Unspecified => write!(f, "Unspecified"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<String> for FilamentMaterial {
    fn from(s: String) -> Self {
        FilamentMaterial::from_str(&s).unwrap()
    }
}

impl From<FilamentMaterial> for String {
    fn from(m: FilamentMaterial) -> String {
        m.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Celsius(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Grams(pub u16);

/// Filament diameter in hundredths of a millimeter (e.g. 175 = 1.75 mm)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(into = "u16", try_from = "u16")]
pub enum FilamentDiameter {
    D175,
    D285,
    Other(u16),
}

impl From<FilamentDiameter> for u16 {
    fn from(d: FilamentDiameter) -> Self {
        match d {
            FilamentDiameter::D175 => 175,
            FilamentDiameter::D285 => 285,
            FilamentDiameter::Other(x) => x,
        }
    }
}

impl TryFrom<u16> for FilamentDiameter {
    type Error = &'static str;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            175 => FilamentDiameter::D175,
            285 => FilamentDiameter::D285,
            x => FilamentDiameter::Other(x),
        })
    }
}

impl FilamentDiameter {
    pub fn mm(&self) -> f32 {
        match self {
            FilamentDiameter::D175 => 1.75,
            FilamentDiameter::D285 => 2.85,
            FilamentDiameter::Other(hundredths) => *hundredths as f32 / 100.0,
        }
    }
}

/// Product Request
#[derive(Deserialize, ToSchema)]
pub struct ProductRequest {
    pub name: String,
    pub price: Cents,
    pub url: String,
    pub material: FilamentMaterial,
    pub diameter: FilamentDiameter,
    pub weight: Grams,
    pub retailer: Retailer,
    pub retailer_product_id: String,
    pub color: String,
}

impl From<ProductRequest> for Product {
    fn from(request: ProductRequest) -> Self {
        Self {
            uuid: SsUuid::new(),
            name: request.name,
            price: request.price,
            price_per_kg: Cents(0), // Calculated in update hook
            url: request.url,
            material: request.material,
            diameter: request.diameter,
            weight: request.weight,
            retailer: request.retailer,
            retailer_product_id: request.retailer_product_id,
            color: request.color,
        }
    }
}

/// Product Response
#[derive(Serialize, ToSchema)]
pub struct ProductResponse {
    uuid: String,
    name: String,
    price: Cents,
    price_per_kg: Cents,
    url: String,
    material: FilamentMaterial,
    diameter: FilamentDiameter,
    weight: Grams,
    retailer: Retailer,
    retailer_product_id: String,
    color: String,
}

impl From<Product> for ProductResponse {
    fn from(product: Product) -> Self {
        Self {
            uuid: product.uuid.to_uuid_string(),
            name: product.name,
            price: product.price,
            price_per_kg: product.price_per_kg,
            url: product.url,
            material: product.material,
            diameter: product.diameter,
            weight: product.weight,
            retailer: product.retailer,
            retailer_product_id: product.retailer_product_id,
            color: product.color,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
pub enum Retailer {
    Amazon,
    Other(String),
}

impl FromStr for Retailer {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Amazon" => Self::Amazon,
            other => Self::Other(other.to_string()),
        })
    }
}

impl std::fmt::Display for Retailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Amazon => write!(f, "Amazon"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<String> for Retailer {
    fn from(s: String) -> Self {
        Retailer::from_str(&s).unwrap()
    }
}

impl From<Retailer> for String {
    fn from(p: Retailer) -> String {
        p.to_string()
    }
}
