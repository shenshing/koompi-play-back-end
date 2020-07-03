#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

extern crate game_back_end;

extern crate diesel;

// use game_back_end::qa::static_rocket_route_info_for_question;
// use game_back_end::datetime::static_rocket_route_info_for_test_time;
// use game_back_end::user::static_rocket_route_info_for_save_player_data;
// use game_back_end::datetime::static_rocket_route_info_for_return_players;
// use game_back_end::datetime::static_rocket_route_info_for_return_top_scorer;
// use game_back_end::datetime::static_rocket_route_info_for_return_winner;
// use game_back_end::qa::static_rocket_route_info_for_question_for_front_end;
// use game_back_end::datetime::{Duration, query_top_scorer, find_winner};
// use game_back_end::models::{PlayerQue};
// use game_back_end::score::static_rocket_route_info_for_private_score;
// use game_back_end::score::static_rocket_route_info_for_public_rank;
use game_back_end::qa::static_rocket_route_info_for_general_question;
use game_back_end::qa::static_rocket_route_info_for_history_question;
use game_back_end::qa::static_rocket_route_info_for_science_question;
use game_back_end::qa::static_rocket_route_info_for_calculating_question;
use game_back_end::score::*;
use game_back_end::models::Player;
use game_back_end::user::save_user_to_db;
use game_back_end::models::Score;
use game_back_end::qa::*;
use game_back_end::user::*;

extern crate rocket_cors;

extern crate userInfo;
use game_back_end::establish_connection;
use game_back_end::schema::users::dsl::*;
// use crate::diesel::QueryDsl;
use crate::diesel::*;
use diesel::dsl::*;
use diesel::query_dsl::RunQueryDsl;

use game_back_end::score::last_five_game_score;


fn main() {
    // use game_back_end::schema::users::dsl::{users, user_email};
    // // use crate::schema::users::dsl::*;
    // // use game_back_end::schema::users::dsl::*;
    // let cors = rocket_cors::CorsOptions::default().to_cors().unwrap();

    // rocket::ignite()
    //     // .mount("/", routes![question_for_front_end])
    //     // .mount("/", routes![test_time])
    //     .mount("/", routes![save_player_data])
    //     // .mount("/", routes![return_players])
    //     // .mount("/", routes![return_top_scorer])
    //     // .mount("/", routes![return_winner]) 
    //     .mount("/", routes![private_score])  
    //     .mount("/", routes![public_rank])
    //     .mount("/", routes![general_question])
    //     .mount("/", routes![history_question])
    //     .mount("/", routes![science_question])
    //     .mount("/", routes![calculating_question])
    //     .mount("/", routes![history_last_five_result])
    //     .mount("/", routes![science_last_five_result])
    //     .mount("/", routes![calculating_last_five_result])
    //     .mount("/", routes![general_last_five_result])
    //     .mount("/", routes![top_ten_history_result])
    //     .mount("/", routes![top_ten_science_result])
    //     .mount("/", routes![top_ten_calculating_result])
    //     .mount("/", routes![top_ten_general_result])
    //     .attach(cors)
    //     .launch();


    // let name = String::from("shing");
    // let password = String::from("123");

    // let result = get_user_by_name_password(name, password).unwrap();

    // println!("{:#?}", result);  
    // hello();      

    // let player = Player {
    //     playername: String::from("d"),
    //     score:      200,
    //     email:      String::from("a@gmai.com")
    // };

    // let conn = establish_connection();

    // let result = save_user_to_db(&conn, player);
    // println!("result: {:#?}", result);

    // let statement = format!("Select * From players Where email='a@gmai.com' Order By score Desc limit 5;");
    // let result: Vec<Score> = sql_query(statement)
    //     .get_results(&establish_connection())
    //     .unwrap();

    // println!("{:#?}", result);

    // let email = String::from("a@gmai.com");
    // let result = last_five_game_score(email);
    // println!("{:#?}", result);

    // let result = random_question_category(String::from("questions"));
    // println!("{:#?}", result);


    // save_to_general_knowledge_db();
    // save_to_history_question_db();
    // save_to_science_question_db();
    // save_to_calculating_question_db();

    // let result = random_question_category(String::from("general"));
    // println!("{:#?}", result);

    // save_question_to_db();

    // let result = random_question_category(String::from("science"));
    // println!("{:#?}", result);

    // let result = random_question();
    // println!("{:#?}", result);


    // let result = get_score().unwrap();
    // println!("{:#?}", result);

    // let email = String::from("b@gmail.com");
    // let result = private_query_history_result(email);
    // println!("{:#?}", result);


    // let category = String::from("calculating");
    // let result = public_query_result(category);
    // println!("{:#?}", result);

    let st = String::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJrb29tcGlQbGF5IiwiZXhwIjoxNTkzMDc0NzQxLCJ1c2VyX2VtYWlsIjoic2hpbmcxQGdtYWlsLmNvbSIsInVzZXJfcm9sZSI6IlVzZXIifQ.UUG291rKWiEWjJHVZnhYkQzWnOFCFervJD8w5x6VqCw");
    let result = decode_token(st);
    println!("{:#?}", result);
}
