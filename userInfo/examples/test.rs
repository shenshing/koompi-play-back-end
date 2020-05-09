#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
// use userInfo::token::decode_token;
// use userInfo::token::Claims;
// use jsonwebtoken::Validation;

// use userInfo::static_rocket_route_info_for_get_profile;
// use userInfo::static_rocket_route_info_for_upload;
use userInfo::get_user_by_name_password;

use userInfo::{Find, filter_user};

use std::fs::File;
use std::io::prelude::*;

extern crate rocket_cors;
// use userInfo::models::sensitive
use userInfo::models::static_rocket_route_info_for_sensitive;
// rocket = { version = "0.4.2", features = ["serde"]}
fn main() {
    // let token = String::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJrb29tcGlQbGF5IiwiZXhwIjoxNjAwNTk0MjQwLCJpYXQiOjE1ODY0MjQ2NDAsImlzcyI6Imtvb21waVBsYXkiLCJzdWIiOiJsb2dpbiIsInVzZXJfbmFtZSI6InNoaW5nIiwidXNlcl9wYXNzd29yZCI6IjEyMyIsInVzZXJfcm9sZSI6IlVzZXIifQ.mi7rDF5AcQcQeUhKJhSTGKTvH5_W9tAE5TydZcPx8jU");
    // let dec_res = jsonwebtoken::decode::<Claims>(&token, "secret".as_ref(), &Validation::default()).unwrap();
    // println!("{:#?}", dec_res);

    // let cors = rocket_cors::CorsOptions::default().to_cors().unwrap();
    
    rocket::ignite()
        // .mount("/", routes![get_profile])
        // .mount("/", routes![upload])
        // .mount("/", routes![])
        .mount("/", routes![sensitive])
        // .attach(cors)
        .launch();

    // let file_name = String::from("a.txt");
    // let file_fmt = format!("/home/koompi/Documents/koompi-play-production/userInfo/image-bank/{}", file_name);
    // let mut file = File::create(file_fmt).unwrap();
    // file.write_all(b"Hello World").unwrap();

    // let token = format!("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJrb29tcGlQbGF5IiwiZXhwIjoxNjAyMTQxMzU1LCJpYXQiOjE1ODc5NzE3NTUsImlzcyI6Imtvb21waVBsYXkiLCJzdWIiOiJsb2dpbiIsInVzZXJfbmFtZSI6InBlcnNvbjMiLCJ1c2VyX3Bhc3N3b3JkIjoiMTIzIiwidXNlcl9yb2xlIjoiVXNlciJ9.DlrZXo_jsZQ6nGKRwMwTG19pQo1emOMmtyeQ4F_X9Nw");
    // let res = filter_user(token);
    
    // match res {
    //     Find::Found => println!("User Found"),
    //     Find::Notfound => println!("User not Found"),
    // }

    get_user_by_name_password(String::from("shing"), String::from("123"));

}