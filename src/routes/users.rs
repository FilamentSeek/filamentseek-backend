use crate::generic::EmailAddress;
use crate::routes::openapi::DummySuccess;
use crate::{
    error::Error,
    generic::{BearerToken, GenericResponse, surrealdb_client},
    models::{session::Session, user::User},
    routes::token::{TokenRequest, TokenResponse, token},
};
use core::str;
use rocket::{
    http::Status,
    response::status,
    serde::{Deserialize, json::Json},
};
use serde::Serialize;
use serde_json::json;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

/// User Response
#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub uuid: String,
    pub is_admin: bool,
    #[schema(value_type = String)]
    pub email: EmailAddress,
}

impl UserResponse {
    pub async fn from_user(user: User) -> Result<Self, Error> {
        Ok(Self {
            uuid: user.uuid.uuid_string(),
            is_admin: user.is_admin,
            email: user.email,
        })
    }
}

/// Get User
#[utoipa::path(
    get,
    path = "/v1/users/{user_id}",
    description = "Get a full User by ID. Only available to admins or the user themselves. If the ID is 'me', the session's user is returned.",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User fetched", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::get("/v1/users/<user_id>")]
pub async fn get_user(
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = get_user_as_self_or_admin(user_id, session).await?;
    Ok(Json(UserResponse::from_user(user).await?))
}

/// Registration Request
#[derive(Deserialize, ToSchema)]
pub struct RegistrationRequest {
    pub username: String,
    pub password: String,
    pub email: EmailAddress,
}

/// Register User
#[utoipa::path(
    post,
    path = "/v1/register_user",
    description = "Register a new User",
    request_body(content = RegistrationRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "User registered and token granted", body = TokenResponse),
        (status = 400, description = "Bad request", body = GenericResponse)
    ),
    tag = "auth"
)]
#[rocket::post("/v1/register_user", format = "json", data = "<registration>")]
pub async fn register(
    registration: Json<RegistrationRequest>,
) -> Result<Json<TokenResponse>, status::Custom<Json<GenericResponse>>> {
    let registration = registration.into_inner();
    let user = User::register(&registration).await?;

    // Log them in
    let token_request =
        TokenRequest::new_password_grant(&user.username.to_string(), &registration.password);

    token(token_request).await
}

/// Retrieves a user by their ID, subject to security checks based on the session.
///
/// This function accepts a user ID and a session. If the ID is "me", it returns the session's user.
/// Otherwise, it returns the user corresponding to the provided ID only if the session's user is
/// the same as the user with the ID or if the session's user is an admin.
async fn get_user_as_self_or_admin(id: &str, session: Session) -> Result<User, Error> {
    if id == "me" {
        session.user().await
    } else {
        match User::db_by_id(&surrealdb_client().await?, id).await? {
            Some(target_user) => {
                let session_user = session.user().await?;

                if target_user.uuid != session_user.uuid() && !session_user.is_admin {
                    return Err(Error::insufficient_permissions());
                }

                Ok(target_user)
            }
            None => Err(Error::new(Status::NotFound, "User not found", None)),
        }
    }
}

/// Change password request
#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[utoipa::path(
    post,
    path = "/v1/users/{user_id}/change_password",
    description = "Change password",
    request_body(content = ChangePasswordRequest, content_type = "application/json"),
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Password changed", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::post(
    "/v1/users/<user_id>/change_password",
    format = "json",
    data = "<request>"
)]
pub async fn change_password(
    user_id: &str,
    request: Json<ChangePasswordRequest>,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let mut user = get_user_as_self_or_admin(user_id, session).await?;

    if user.verify_password(&request.old_password).is_err() {
        return Err(Error::new(Status::Unauthorized, "Invalid password", None).into());
    }

    user.set_password(&request.new_password).await?;
    Ok(Json(GenericResponse::success()))
}

/// User Request
#[derive(Deserialize, ToSchema)]
pub struct UserRequest {
    #[schema(value_type = String)]
    pub email: Option<EmailAddress>,

    /// Only admins can change the password of a user with this endpoint.
    /// Users can change their own password by using the change_password endpoint.
    /// This is because users must provide their current password to change it.
    pub password: Option<String>,
}

/// Update User
#[utoipa::path(
    patch,
    path = "/v1/users/{user_id}",
    description = "Update a User by ID",
    request_body(content = UserRequest, content_type = "application/json"),
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 400, description = "Bad request", body = GenericResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::patch("/v1/users/<user_id>", format = "json", data = "<request>")]
pub async fn update_user(
    user_id: &str,
    request: Json<UserRequest>,
    bearer_token: BearerToken,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let mut user = get_user_as_self_or_admin(user_id, session).await?;
    let mut updates = vec![];

    if let Some(email) = &request.email {
        if User::db_search_one(
            &surrealdb_client().await.map_err(Into::<Error>::into)?,
            "email",
            email.clone(),
        )
        .await
        .map_err(Into::<Error>::into)?
        .is_none()
        {
            return Err(Error::bad_request("Email is taken.").into());
        }

        updates.push(("email", json!(email)));
        user.email = email.to_owned();
    }

    if let Some(password) = &request.password {
        if user.is_admin {
            user.set_password(password).await?;
        } else {
            return Err(Error::bad_request(
                "Users can only change their own password with the change_password endpoint",
            )
            .into());
        }
    }

    user.db_update_fields(
        &surrealdb_client().await.map_err(Into::<Error>::into)?,
        updates,
    )
    .await
    .map_err(Into::<Error>::into)?;

    Ok(Json(UserResponse::from_user(user).await?))
}

/// Delete User
#[utoipa::path(
    delete,
    path = "/v1/users/{user_id}",
    description = "Delete a User by ID",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::delete("/v1/users/<user_id>")]
pub async fn delete_user(
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = get_user_as_self_or_admin(user_id, session).await?;

    user.db_delete(&surrealdb_client().await.map_err(Into::<Error>::into)?)
        .await
        .map_err(Into::<Error>::into)?;

    Ok(Json(GenericResponse::success()))
}

/// Get all Users
#[utoipa::path(
    get,
    path = "/v1/users",
    description = "Get all Users. Only available to admins.",
    responses(
        (status = 200, description = "List of users", body = [UserResponse]),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::get("/v1/users")]
pub async fn get_users(
    bearer_token: BearerToken,
) -> Result<Json<Vec<UserResponse>>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = session.user().await?;

    if !user.is_admin {
        return Err(Error::insufficient_permissions().into());
    }

    let users = User::db_all(&surrealdb_client().await.map_err(Into::<Error>::into)?)
        .await
        .map_err(Into::<Error>::into)?;

    let mut response = Vec::with_capacity(users.len());

    for user in users {
        response.push(UserResponse::from_user(user).await?);
    }

    Ok(Json(response))
}
