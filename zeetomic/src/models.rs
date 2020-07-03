// #[macro_use]
// extern crate diesel;
// use diesel::prelude::*;

// #[macro_use]
extern crate serde;

extern crate serde_json;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct st {
    pub string:  String
}


// use super::schema::zee_wallet;
use crate::schema::zee_wallet;
#[derive(Insertable, Deserialize, Debug, Clone)]
#[table_name="zee_wallet"]
pub struct Wallet {
    pub wallet_id:  String,
    pub wallet:     String,
    pub email:      String
}

#[derive(Queryable, Deserialize, Serialize, Insertable)]
#[table_name="zee_wallet"]
pub struct _Wallet {
    pub id:         i32,
    pub wallet_id:  String,
    pub wallet:     String,
    pub email:      String
}

use rocket::{Request, Data, Outcome::*};
use rocket::data::{self, FromDataSimple};
impl FromDataSimple for Wallet {
    type Error = String;

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, String> {
        let new_wallet = Wallet {
            wallet_id:  String::from("default"),
            wallet:     String::from("default"),
            email:      String::from("default")
        };
        Success(new_wallet)
    }
}


#[derive(Deserialize, Serialize)]
pub struct stringObj {
    pub string: String
}

impl FromDataSimple for stringObj {
    type Error = String;

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, String> {

        let new_obj = stringObj {
            string: String::from("default string object"),
        };

        Success(new_obj)
    }
}