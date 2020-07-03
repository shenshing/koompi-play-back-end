use userInfo::models::ApiKey;
use userInfo::token::decode_token;

use rocket_contrib::json::Json;
use crate::models::{Wallet, stringObj};
use crate::establish_connection;
use diesel::prelude::*;
#[post("/create-wallet", data="<new_wallet>")]
// pub fn save_wallet_to_db(key: ApiKey, new_wallet: Json<Wallet>) -> Json<stringObj> {
pub fn save_wallet_to_db(new_wallet: Json<Wallet>) -> Json<stringObj> {
    use crate::schema::zee_wallet;

    // let wallet_data = new_wallet.into_inner().clone();

    // let token = key.into_inner();
    // let claim = decode_token(token.clone().to_string());
    // let save_email = claim.claims.user_email;
    // let wallet_ = new_wallet.into_inner();

    let save_wallet = Wallet {
        wallet_id: new_wallet.wallet_id.clone(),
        wallet: new_wallet.wallet.clone(),
        email:  new_wallet.email.clone()
    };

    let insert_result = diesel::insert_into(zee_wallet::table)
        .values(&save_wallet)
        .execute(&establish_connection());

    match insert_result {
        Ok(ok) => return Json(
            stringObj {
                string: String::from("Successfully create wallet")
            } 
        ),
        Err(err) => return Json(
            stringObj {
                string: String::from("Something went wrong")
            }
        )
    }
}

use userInfo::Find;
pub fn filter_wallet(email_: String) -> Find {
    // use self::schema::zee_wallet::dsl::{zee_wallet, email};
    use crate::schema::zee_wallet::dsl::{zee_wallet};
    use crate::schema::zee_wallet::columns::email;
    let email_pattern = format!("%{}%", format_args!("{}", email_));

    let result = zee_wallet.filter(email.like(email_pattern))
        .execute(&establish_connection())
        .unwrap();
    if(result == 0) {
        return Find::Notfound;
    } else {
        return Find::Found;
    }
}

use userInfo::filter_user;
use crate::models::_Wallet;
#[get("/get-wallet")]
// pub fn get_wallet_info(key: ApiKey) -> Json<_Wallet> {
pub fn get_wallet_info(key: ApiKey) -> Json<_Wallet> {
    use crate::schema::zee_wallet::dsl::{zee_wallet};
    use crate::schema::zee_wallet::columns::email;

    let token = key.into_inner();
    let claim = decode_token(token.clone().to_string());
    let user_email = claim.claims.user_email;

    let find_result = filter_user(token.clone());


    if(filter_wallet(user_email.clone()) == Find::Found) {
        let email_pattern = format!("%{}%", format_args!("{}", user_email));
        let wallet: _Wallet = zee_wallet.filter(email.like(email_pattern))
            .get_result(&establish_connection())
            .unwrap();
        return Json(wallet);
    } else {
        // return format!("No wallet found for user");
        // return Json(Err(stringObj {
        //     string: String::from("No wallet found for users"),
        // }))
        return Json(_Wallet {
            id: 0i32,
            wallet_id: String::from("default"),
            wallet: String::from("default"),
            email: String::from("default")
        })
    }

}