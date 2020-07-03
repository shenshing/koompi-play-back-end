// extern crate game_back_end;
extern crate diesel;
use crate::models::{Score, PlayerQue};
use crate::establish_connection;
// use diesel::dsl::*;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use diesel::dsl::*;


use userInfo::token::decode_token;
use userInfo::models::ApiKey;

extern crate rocket_contrib;
use rocket_contrib::json::Json;

pub fn hello() {
    println!("Hello from score.rs file");
}


pub fn last_five_game_score(player_email: String) -> Result<Vec<PlayerQue>, String> {
    use crate::schema::users::dsl::{users};
    use crate::schema::users::columns::user_email;
    let mut results: Vec<PlayerQue> = Vec::new();

    let email_pattern = format!("%{}%", format_args!("{}", player_email.clone()));

    let result = users.filter(user_email.like(email_pattern))
        .execute(&establish_connection());

    match result {
        Ok(ok) => {
            let statement = format!("Select * From player Where email='{}' Order By score Desc limit 5;", player_email);
            // println!("ok: {}", ok);
            results = sql_query(statement)
                .get_results(&establish_connection())
                .unwrap();
            // println!("{:#?}", result);
            return Ok(results);
        },
        Err(err) => {
            // println!("{:#?}", err);
            return Err(format!("No user found"));
        }
    }
    // return results;
}

pub fn select_top_ten() -> Result<Vec<PlayerQue>, String> {
    let statement = format!("Select * From player Order By score Desc limit 10;");

    let result = sql_query(statement)
        .get_results(&establish_connection());
        // .unwrap();

    match result {
        Ok(data) => {
            return Ok(data);
        },
        Err(err) => {
            return Err(err.to_string());
        }
    }
    // return result;
}   

#[get("/user-score")]
// pub fn private_score(key: ApiKey) -> Result<Json<PlayerQue>, String> {
pub fn private_score(key: ApiKey) -> Json<Vec<PlayerQue>> {
    let token = key.into_inner();

    let decode = decode_token(token.clone().to_string());
    let email = decode.claims.user_email;

    return Json(last_five_game_score(email).unwrap());
}

#[get("/public-rank")]
pub fn public_rank(key: ApiKey) -> Json<Vec<PlayerQue>> {
    return Json(select_top_ten().unwrap());
    // let mut all_data = get_score().unwrap();
    // all_data.sort_by(|a, b| b.score.cmp(&a.score));
    // return Json(all_data);
}


pub fn get_score() -> Result<Vec<PlayerQue>, diesel::result::Error> {
    let statement = format!("Select * From players;");
    let result = sql_query(statement)
        .get_results(&establish_connection());

    match result {
        Ok(ok) => return Ok(ok),
        Err(err) => return  Err(err),
    }
    return result;
}

// extern crate diesel;
use diesel::prelude::*;
// use diesel::pg::PgConnection;
use diesel::dsl::*;
pub fn private_query_result(given_email: String, category: String) -> Result<Vec<PlayerQue>, String> {
    use crate::schema::users::dsl::users;
    use crate::schema::users::columns::user_email;

    let mut results: Vec<PlayerQue> = Vec::new();

    let result = users.filter(user_email.eq(given_email.clone()))
        .execute(&establish_connection());

    match result {
        Ok(ok) => {
            // let statement = format!("Select * From player Where email='{}' And quiz_category='{}' Order By score Desc limit 5;", given_email.clone(), category.clone());
            let statement = format!("Select * From player Where email='{}'  and quiz_category='{}' Order By playdate Desc Limit 5;", given_email, category);
            results = sql_query(statement)
                .get_results(&establish_connection())
                .unwrap();
            return Ok(results);
        },
        Err(err) => {
            return Err(format!("No user found"));
        }
    }
}

#[get("/last-history-result")]
pub fn history_last_five_result(key: ApiKey) -> Json<Vec<PlayerQue>> {
    let token = key.into_inner();
    let decode = decode_token(token.clone().to_string());
    let email = decode.claims.user_email;

    let category = String::from("history");
    let data = private_query_result(email, category);
    return Json(data.unwrap());
}

#[get("/last-science-result")]
pub fn science_last_five_result(key: ApiKey) -> Json<Vec<PlayerQue>> {
    let token = key.into_inner();
    let decode = decode_token(token.clone().to_string());
    let email = decode.claims.user_email;

    let category = String::from("science");
    let data = private_query_result(email, category);
    return Json(data.unwrap());
}

#[get("/last-calculating-result")]
pub fn calculating_last_five_result(key: ApiKey) -> Json<Vec<PlayerQue>> {
    let token = key.into_inner();
    let decode = decode_token(token.clone().to_string());
    let email = decode.claims.user_email;

    let category = String::from("calculating");
    let data = private_query_result(email, category);
    return Json(data.unwrap());
}

#[get("/last-general-result")]
pub fn general_last_five_result(key: ApiKey) -> Json<Vec<PlayerQue>> {
    let token = key.into_inner();
    let decode = decode_token(token.clone().to_string());
    let email = decode.claims.user_email;

    let category = String::from("general");
    let data = private_query_result(email, category);
    return Json(data.unwrap());
}

pub fn public_query_result(category: String) -> Result<Vec<PlayerQue>, String> {
    let statement = format!("Select * From player Where quiz_category='{}' Order By score Desc Limit 10;", category);
    let result = sql_query(statement)
        .get_results(&establish_connection());

    match result {
        Ok(data) => {
            return Ok(data);
        },
        Err(err) => {
            return Err(err.to_string());
        }
    }
}

#[get("/history-top")]
pub fn top_ten_history_result() -> Json<Vec<PlayerQue>> {
    let category = String::from("history");
    let result = public_query_result(category).unwrap();

    return Json(result);
}

#[get("/science-top")]
pub fn top_ten_science_result() -> Json<Vec<PlayerQue>> {
    let category = String::from("science");
    let result = public_query_result(category).unwrap();

    return Json(result);
}

#[get("/calculating-top")]
pub fn top_ten_calculating_result() -> Json<Vec<PlayerQue>> {
    let category = String::from("calculating");
    let result = public_query_result(category).unwrap();

    return Json(result);
}

#[get("/general-top")]
pub fn top_ten_general_result() -> Json<Vec<PlayerQue>> {
    let category = String::from("general");
    let result = public_query_result(category).unwrap();

    return Json(result);
}