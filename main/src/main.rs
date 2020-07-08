#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;


extern crate userInfo;
use userInfo::insert_user;

extern crate game_back_end;
use self::game_back_end::user::*;
use self::game_back_end::qa::*;
use self::game_back_end::score::*;
// use self::game_back_end::*;

extern crate zeetomic;
use self::zeetomic::wallet::*;
extern crate diesel;
use self::userInfo::*;
extern crate rocket_cors;

use rocket_contrib::templates::Template;

use rocket::http::Method;
use rocket_cors::{
    AllowedHeaders, AllowedOrigins, Error, 
    Cors, CorsOptions 
};

//
fn main() {
    let allowed_origins = AllowedOrigins::all();

    let allow = AllowedHeaders::all();
    let cors = CorsOptions { 
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post].into_iter().map(From::from).collect(), 
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("error while building CORS");

    println!("cors option: {:#?}", cors);

    rocket::ignite()
        .mount("/", routes![hello,
                            register, 
                            userData,
                            updateName,
                            updatePassword,
                            updateProfile,
                            updateRole,
                            updatePhone,
                            self_destroy,
                            admin_dashboard, 
                            user_dashboard, 
                            error_dashboard,
                            uploadprofile,
                            get_profile,
                            save_player_data,


                            all_type_register,
                            all_type_login,
                            // question_for_front_end,

                            //version0.2
                            private_score,
                            public_rank,
                            general_question,
                            history_question,
                            science_question,
                            calculating_question,

                            history_last_five_result,
                            science_last_five_result,
                            calculating_last_five_result,
                            general_last_five_result,

                            top_ten_history_result,
                            top_ten_science_result,
                            top_ten_calculating_result,
                            top_ten_general_result,

                            save_wallet_to_db,
                            get_wallet_info
                            ])
        .attach(cors)
        .attach(Template::fairing())
        .launch(); 


    
}

