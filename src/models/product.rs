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
    pub nozzle_temp: Option<TemperatureSpec>,
    pub bed_temp: Option<TemperatureSpec>,
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
            UPDATE {} SET price_per_kg = {} WHERE uuid = {};
            "#,
            Self::table(),
            price_per_kg,
            serde_json::to_string(&self.uuid())?
        );

        client.query(&query).await?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Cents(pub u32);

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum TemperatureSpec {
    /// Exact value (e.g. vendor says "200°C only")
    Exact(Celsius),
    /// Inclusive range (e.g. "190–220°C")
    Range { min: Celsius, max: Celsius },
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
    pub nozzle_temp: Option<TemperatureSpec>,
    pub bed_temp: Option<TemperatureSpec>,
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
            nozzle_temp: request.nozzle_temp,
            bed_temp: request.bed_temp,
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
    nozzle_temp: Option<TemperatureSpec>,
    bed_temp: Option<TemperatureSpec>,
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
            nozzle_temp: product.nozzle_temp,
            bed_temp: product.bed_temp,
        }
    }
}
