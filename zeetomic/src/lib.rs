#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;

#[macro_use]
extern crate diesel;
use diesel::prelude::*;

extern crate serde;

extern crate userInfo;

use std::env;
use dotenv::dotenv;
use diesel::pg::PgConnection;
pub fn establish_connection() -> PgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

pub mod schema;
pub mod models;
pub mod wallet;
