#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;


extern crate userInfo;
use userInfo::insert_user;
extern crate game_back_end;
use self::game_back_end::user::*;
use self::game_back_end::qa::*;

extern crate diesel;
use self::userInfo::*;
extern crate rocket_cors;

use rocket_contrib::templates::Template;

use rocket::http::Method;
use rocket_cors::{
    AllowedHeaders, AllowedOrigins, Error, 
    Cors, CorsOptions 
};

fn main() {

    let allowed_origins = AllowedOrigins::all();

    let allow = AllowedHeaders::all();
    let cors = CorsOptions { 
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post].into_iter().map(From::from).collect(), 
        // allowed_headers: AllowedHeaders::some(&[
        //     "Authorization",
        //     "Accept",
        //     "Access-Control-Allow-Origin",
        //     // Access-Control-Allow-Origin::ANY, 
        //     "token",
	    //     "Content-Type",
        //     "*",
        // ]),

        allowed_headers: AllowedHeaders::all(),

        // allowed_headers: allow,
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("error while building CORS");

    println!("cors option: {:#?}", cors);

    // rocket::ignite()
    //     .mount("/", routes![register, 
    //                         login, 
    //                         admin_dashboard, 
    //                         user_dashboard, 
    //                         error_dashboard,
    //                         // check_user_role,
    //                         self_destroy,
    //                         updateName,
    //                         updatePassword,
    //                         updateProfile,
    //                         updateRole,
    //                         updatePhone,
    //                         // displayUser,
    //                         // userData,
    //                         test_token,
    //                         // upload_profile, 
    //                         uploadprofile,
    //                         get_profile,
	// 		                test_login,
	// 		                // userData1,
    //                         userData2,
    //                         save_player_data,
    //                         hello])
    //     .attach(cors)
    //     .attach(Template::fairing())
    //     .launch(); 

    rocket::ignite()
        .mount("/", routes![hello,
                            register, 
                            // login, 
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
                            question_for_front_end,
                            // userData1,
                            // register1,
                            // test_token,
                            // upload_profile, 
			                // test_login,
			                // userData1,
                            // userData2,
                            // check_user_role,
                            // displayUser,
                            ])
        .attach(cors)
        .attach(Template::fairing())
        .launch(); 


    
}

