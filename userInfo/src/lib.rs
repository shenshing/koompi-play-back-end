#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use]
extern crate diesel;
extern crate dotenv;

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

use self::email_addr::DuplicateEmail;
use self::models::{User};
pub fn insert_user(conn: &PgConnection, user: User) -> DuplicateEmail {
    use schema::users;
    
    let new_user = User {
        user_name:      user.user_name,
        user_gender:    user.user_gender.clone(),
        user_email:     user.user_email,
        user_password:  user.user_password,
        user_profile:   Some(set_default_profile(user.user_gender.clone())),
        user_role:      user.user_role,
        phone_number:   user.phone_number,
    };

    let insert_result = match diesel::insert_into(users::table)
        .values(new_user)
        .execute(conn) {
            Ok(ok) => DuplicateEmail::Nonexist,
            Err(err) => DuplicateEmail::Exist,
    };
    return insert_result;
}

use self::models::{_User};
pub fn get_user(conn: &PgConnection) -> Vec<_User>{
    use self::schema::users::dsl::*;

    let user_list = users.load::<_User>(conn)
        .expect("Error retrieve user from database");
    return user_list;
}

#[derive(Debug, PartialEq)]
pub enum deleteMessage {
    Success,
    Unsuccess,
}

use self::diesel::prelude::*;
use crate::schema::users;
pub fn remove_user(userName: String, userPassword: String) -> deleteMessage {
    use self::schema::users::dsl::*;

    let name_pattern = format!("%{}%", format_args!("{}", userName));
    let password_pattern = format!("%{}%", format_args!("{}", userPassword));

    let connection = establish_connection();
    let delete_user = diesel::delete(users.filter(user_name.like(name_pattern)).filter(user_password.like(password_pattern)))
        .execute(&connection);
    if(delete_user == Ok(1)) {
        return deleteMessage::Success;
    } else {
        return deleteMessage::Unsuccess;
    }
}

//////////////////////////////////////////
#[derive(Debug, PartialEq)]
pub enum Find {
    Found,
    Notfound,
}
pub fn filter_user(token: String) -> Find {
    use self::schema::users::dsl::{users, user_name, user_password};
    let dec_token = decode_token(token);

    // println!("{:#?}", dec_token);
    let name = dec_token.claims.user_name;
    let password = dec_token.claims.user_password;

    let result = users.filter(user_name.like(name))
        .filter(user_password.like(password))
        .execute(&establish_connection())
        // .get_result(&establish_connection())
        .unwrap();
    if(result == 0) {
        return Find::Notfound;
    } else {
        return Find::Found;
    }
}

pub fn get_user_by_name_password(name: String, password: String) -> Result<_User, diesel::result::Error> {
// pub fn get_user_by_name_password(name: String, password: String) {
    use self::schema::users::dsl::{users, user_name, user_password};

    // let result = users.filter(user_name.like(name))
    //     .filter(user_password.like(password))
    //     .get_result(&establish_connection());
        // .unwrap();


    // println!("result: {:#?}", result);
    // if(result == 0) {
    //     return Err(String::from("not found"));
    // } else {
    //     return Ok(result);
    // }
    match users.filter(user_name.eq(name))
        .filter(user_password.eq(password))
        .get_result::<_User>(&establish_connection()) {
        Ok(user) => return Ok(user),
        Err(err) => return Err(err),
    }
    // return Ok(result);
}




#[derive(Debug, PartialEq)]
pub enum updateMessage {
    Success,
    Unsuccess,
}

pub fn update_name(oldUserName: String, userPassword: String, newUserName: String) -> updateMessage {
    use self::schema::users::dsl::{users, user_name};

    let update_name = diesel::update(users.filter(user_name.eq(oldUserName))
        .filter(user_password.eq(userPassword)))
        .set(user_name.eq(newUserName))
        .execute(&establish_connection());
    if(update_name == Ok(1)) {
        return updateMessage::Success;
    } else {
        return updateMessage::Unsuccess;
    }
}

pub fn update_password(userName: String, userPassword: String, newUserPassword: String) -> updateMessage {
    use self::schema::users::dsl::{users, user_name, user_password};

    let update_password = diesel::update(users.filter(user_name.eq(userName))
        .filter(user_password.eq(userPassword)))
        .set(user_password.eq(newUserPassword))
        .execute(&establish_connection());
    if(update_password == Ok(1)) {
        return updateMessage::Success;
    } else {
        return updateMessage::Unsuccess;
    }
}

pub fn update_profile(userName: String, userPassword: String, newUserProfile: String) -> updateMessage {
    use self::schema::users::dsl::{users, user_profile, user_name};

    let update_profile = diesel::update(users.filter(user_name.eq(userName))
        .filter(user_password.eq(userPassword)))
        .set(user_profile.eq(newUserProfile))
        .execute(&establish_connection());
    if(update_profile == Ok(1)) {
        return updateMessage::Success;
    } else {
        return updateMessage::Unsuccess;
    }
}

pub fn update_role(userName: String, userPassword: String, newUserRole: String) -> updateMessage {
    use self::schema::users::dsl::{users, user_name, user_role};

    let update_role = diesel::update(users.filter(user_name.eq(userName))
        .filter(user_password.eq(userPassword)))
        .set(user_role.eq(newUserRole))
        .execute(&establish_connection());
    if(update_role == Ok(1)) {
        return updateMessage::Success;
    } else {
        return updateMessage::Unsuccess;
    }
}

pub fn update_phone(userName: String, userPassword: String, newUserPhone: String) -> updateMessage {
    use self::schema::users::dsl::{users, user_name, phone_number};

    let update_phone = diesel::update(users.filter(user_name.eq(userName))
        .filter(user_password.eq(userPassword)))
        .set(phone_number.eq(newUserPhone))
        .execute(&establish_connection());
    if(update_phone == Ok(1)) {
        return updateMessage::Success;
    } else {
        return updateMessage::Unsuccess;
    }
}

//change path to localhost
pub fn set_default_profile(gender: String) -> String {
    let mut default_profile = String::new();
    if(gender == String::from("Male")) {
        default_profile = String::from("http://localhost:8000/get_profile/EOk1");
    } else {
        default_profile = String::from("http://localhost:8000/get_profile/cQrw");
    }
    return default_profile;
}


/*move this function to last after successful*/
const name_length: usize = 4;
use rocket_multipart_form_data::{
    MultipartFormData, MultipartFormDataError, MultipartFormDataField, MultipartFormDataOptions,
    RawField,
};
use rocket::Data;
use rocket::http::ContentType;


// #[post("/upload", data = "<data>")]
// pub fn upload_profile(content_type: &ContentType, data: Data) -> Result<RawResponse, &'static str> {
//     let mut options = MultipartFormDataOptions::new();
//     options.allowed_fields.push(
//         MultipartFormDataField::raw("image")
//             .size_limit(32 * 1024 * 1024)
//             .content_type_by_string(Some(mime::IMAGE_STAR))
//             .unwrap(),
//     );

//     let mut multipart_form_data = match MultipartFormData::parse(content_type, data, options) {
//         Ok(multipart_form_data) => multipart_form_data,
//         Err(err) => {
//             match err {
//                 MultipartFormDataError::DataTooLargeError(_) => {
//                     return Err("The file is too large.")
//                 }
//                 MultipartFormDataError::DataTypeError(_) => {
//                     return Err("The file is not an image.")
//                 }
//                 _ => panic!("{:?}", err),
//             }
//         }
//     };

//     let image = multipart_form_data.raw.remove("image");

//     match image {
//         Some(image) => {
//             match image {
//                 RawField::Single(raw) => {
//                     let content_type = raw.content_type;
//                     let file_name = format!("{}", PasteID::new(name_length));
//                     let data = raw.raw;
                    
//                     // let file_fmt = format!("/home/koompi/Documents/koompi-play-production/upload_retrieve_img/image-bank/{}", file_name);
//                                             // /home/koompi/Documents/koompi-play-production/userInfo/image-bank
//                     let file_fmt = format!("/home/koompi/Documents/koompi-play-production/userInfo/image-bank/{}", file_name);
//                     let mut file = File::create(file_fmt).unwrap();
                    
//                     let write_res = file.write(&data[0..]).unwrap();

//                     Ok(RawResponse::from_vec(data, Some(file_name), content_type))
//                 }
//                 RawField::Multiple(_) => unreachable!(),
//             }
//         }
//         None => Err("Please input a file."),
//     }
// }



//upload to specific users
#[post("/uploadto/<token>", data = "<data>")]
pub fn upload_profile(content_type: &ContentType, data: Data, token: String) -> Result<RawResponse, &'static str> {
    
    let token_decode = decode_token(token.clone());
    let name =  token_decode.claims.user_name;
    let password = token_decode.claims.user_password;

    let res = filter_user(token);
    
    match res {
        Find::Found => {
            //user found
            let mut options = MultipartFormDataOptions::new();
            options.allowed_fields.push(
                MultipartFormDataField::raw("image")
                    .size_limit(32 * 1024 * 1024)
                    .content_type_by_string(Some(mime::IMAGE_STAR))
                    .unwrap(),
            );

            let mut multipart_form_data = match MultipartFormData::parse(content_type, data, options) {
                Ok(multipart_form_data) => multipart_form_data,
                Err(err) => {
                    match err {
                        MultipartFormDataError::DataTooLargeError(_) => {
                            return Err("The file is too large.")
                        }
                        MultipartFormDataError::DataTypeError(_) => {
                            return Err("The file is not an image.")
                        }
                        _ => panic!("{:?}", err),
                    }
                }
            };

            let image = multipart_form_data.raw.remove("image");

            match image {
                Some(image) => {
                    match image {
                        RawField::Single(raw) => {
                            let content_type = raw.content_type;
                            let file_name = format!("{}", PasteID::new(name_length));
                            let data = raw.raw;
                            
                            let file_fmt = format!("/home/koompi/Documents/koompi-play-production/userInfo/image-bank/{}", file_name);
                            let mut file = File::create(file_fmt).unwrap();
                            
                            let write_res = file.write(&data[0..]).unwrap();
                                /*update user profile image*/
                                let new_profile_path = format!("http://localhost:8000/get_profile/{}", file_name);
                                
                                if(update_profile(name.clone(), password.clone(), new_profile_path.clone()) == updateMessage::Success) {
                                    return Err("update user profile Successfully");
                                } else if(update_profile(name.clone(), password.clone(), new_profile_path.clone()) == updateMessage::Unsuccess) {
                                    return Err("update user profile Unsuccessful");
                                } else {
                                    // let st = format!("Something went wrong when trying to update \"userName : {} \" to \"userName : {} \"", userName.clone(), new_name.clone());
                                    // let st = format!("Something wen wrong when trying to update profile");
                                    return Err("Something wen wrong when trying to update profile");
                                }
                                
                                /************************/
                            Ok(RawResponse::from_vec(data, Some(file_name), content_type))
                        }
                        RawField::Multiple(_) => unreachable!(),
                    }
                }
                None => Err("Please input a file."),
            }
        },
        Find::Notfound => {
            return Err("no user found");
        }
    }

    
    
}

//end upload to specific user
mod paste_id;
use std::fs::File;
use std::io::prelude::*;

use crate::paste_id::PasteID;
extern crate rocket_multipart_form_data;
extern crate rocket_raw_response;

use rocket_multipart_form_data::mime;
use rocket_raw_response::RawResponse;

#[get("/get_profile/<id>")]
pub fn get_profile(id: PasteID<'_>) -> Result<RawResponse, &'static str> {
    // let file_format = format!("image-bank/{id}", id = id);
    let file_format = format!("/home/koompi/Documents/koompi-play-production/userInfo/image-bank/{id}", id = id);
    let mut file = File::open(file_format).unwrap();

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    println!("{:?}", buffer);
    let name = String::from("a");
    Ok(RawResponse::from_vec(buffer, Some(name), Some(mime::IMAGE_STAR)))
}


/*end */
extern crate rocket_contrib;
use rocket_contrib::json::Json;
mod email_addr;
use email_addr::{Validate_Email, valid_email};


use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct Token {
    token: String,
}

#[post("/test_token", data = "<token>")]
pub fn test_token(token: Json<Token>) -> Json<Token> {
    Json(
        Token {
            token: String::from("hello")
        }
    )
}


#[post("/register", data = "<user>")]
pub fn register(user: Json<User>) -> String { 
    let conn = establish_connection();
    
    use diesel::select;
    let now = select(diesel::dsl::now).get_result::<SystemTime>(&conn).unwrap();

    let new_user = user.into_inner();

    println!("new_user : {:#?}", new_user);

    if(insert_user(&conn, new_user.clone()) == DuplicateEmail::Nonexist) {
        return format!("Register complete!!!")
    } else if (insert_user(&conn, new_user.clone()) == DuplicateEmail::Exist) {
        return format!("Email already exist")
    } else {
        return format!("Something went wrong when trying to Registering");
    }
}

use self::models::{loginInfo};
#[post("/login", data = "<log_info>")]
pub fn login(log_info: Json<loginInfo>) -> Json<String> {
    use self::schema::users::dsl::*;

    //print header



    let connection = establish_connection();

    let user_list = get_user(&connection);
    let mut string = String::new();

    for _user in user_list.iter() {
        if(_user.user_name.trim() == log_info.user_name.trim()) {
            if(_user.user_password.trim() == log_info.user_password.trim()) {
                let role = _user.user_role.as_ref().unwrap();
                string = generate_token(_user.user_name.to_string(),   
                                        _user.user_password.to_string(), 
                                        role.to_string());
                break;
            } else {
                string = format!("Log in Failed");  
            }
        } else {
            string = format!("Log in Failed");
        }
    }
    return Json(string);
}

#[post("/delete", data = "<token_>")]
pub fn self_destroy(token_: Json<Token>) -> String {
    let dec_res = decode_token(token_.token.clone());
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;

    if(remove_user(userName.clone(), userPassword.clone()) == deleteMessage::Success) {
        format!("user delete successfull")
    } else if (remove_user(userName.clone(), userPassword.clone()) == deleteMessage::Unsuccess) {
        format!("user delete unsuccessful") 
    } else {
        format!("Something went wrong when delete user")
    }
}

use crate::schema::users::columns::user_password;
use self::models::updateItem;
#[post("/updateName", data = "<newInfo>")]
pub fn updateName(newInfo: Json<updateItem>) -> String {
    let dec_res = jsonwebtoken::decode::<Claims>(&newInfo.token.clone(), "secret".as_ref(), &Validation::default()).unwrap();
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;
    let new_name = newInfo.newName.clone();

    if(update_name(userName.clone(), userPassword.clone(), new_name.clone()) == updateMessage::Success) {
        format!("update userName Successfully")
    } else if (update_name(userName.clone(), userPassword.clone(), new_name.clone()) == updateMessage::Unsuccess) {
        format!("update userName Unsuccessful")
    } else {
        format!("Something went wrong when trying to update \"userName : {} \" to \"userName : {} \"", userName.clone(), new_name.clone())
    }
}

#[post("/updatePassword", data = "<newInfo>")]
pub fn updatePassword(newInfo: Json<updateItem>) -> String {
    let dec_res = jsonwebtoken::decode::<Claims>(&newInfo.token.clone(), "secret".as_ref(), &Validation::default()).unwrap();
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;
    let new_password = newInfo.newPassword.clone();

    if(update_password(userName.clone(), userPassword.clone(), new_password.clone()) == updateMessage::Success) {
        format!("update user password Successfully")
    } else if (update_password(userName.clone(), userPassword.clone(), new_password.clone()) == updateMessage::Unsuccess) {
        format!("update user password Unsuccessful")
    } else {
        format!("Something went wrong when trying to update Password")
    }
}

#[post("/updateProfile", data = "<newInfo>")]
pub fn updateProfile(newInfo: Json<updateItem>) -> String {
    let dec_res = jsonwebtoken::decode::<Claims>(&newInfo.token.clone(), "secret".as_ref(), &Validation::default()).unwrap();
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;
    let new_profile = newInfo.newProfile.clone();

    if(update_profile(userName.clone(), userPassword.clone(), new_profile.clone()) == updateMessage::Success) {
        format!("update user profile Successfully")
    } else if (update_profile(userName.clone(), userPassword.clone(), new_profile.clone()) == updateMessage::Unsuccess) {
        format!("update user profile Unsuccessful")
    } else {
        format!("Something went wrong when trying to update Profile")
    }
}

#[post("/updateRole", data = "<newInfo>")]
pub fn updateRole(newInfo: Json<updateItem>) -> String {
    let dec_res = jsonwebtoken::decode::<Claims>(&newInfo.token.clone(), "secret".as_ref(), &Validation::default()).unwrap();
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;
    let new_role = newInfo.newRole.clone();

    if(update_role(userName.clone(), userPassword.clone(), new_role.clone()) == updateMessage::Success) {
        format!("update user role Successfully")
    } else if (update_role(userName.clone(), userPassword.clone(), new_role.clone()) == updateMessage::Unsuccess) {
        format!("update user role Unsuccessful")
    } else {
        format!("Something went wrong when trying to update Role")
    }
}

#[post("/updatePhone", data = "<newInfo>")]
pub fn updatePhone(newInfo: Json<updateItem>) -> String {
    let dec_res = jsonwebtoken::decode::<Claims>(&newInfo.token.clone(), "secret".as_ref(), &Validation::default()).unwrap();
    let userName = dec_res.claims.user_name;
    let userPassword = dec_res.claims.user_password;
    let new_role = newInfo.newPhone.clone();

    if(update_phone(userName.clone(), userPassword.clone(), new_role.clone()) == updateMessage::Success) {
        format!("update user phone number Successfully")
    } else if (update_phone(userName.clone(), userPassword.clone(), new_role.clone()) == updateMessage::Unsuccess) {
        format!("update user phone number Unsuccessful")
    } else {
        format!("Something went wrong when trying to update Phone Number")
    }
}

#[get("/display")]
pub fn displayUser() -> String {
    let from_db = get_user(&establish_connection());
    let json_str = serde_json::to_string_pretty(&from_db).unwrap();
    return json_str;
}

//eg: localhost::8000/shing (display username after route to get "user information")
#[post("/userData", data = "<token_>")]
pub fn userData(token_: Json<Token>) -> Json<_User> {
    use self::schema::users::dsl::{users, user_name, user_password};
    let find_result = filter_user(token_.token.clone());

    let decode = decode_token(token_.token.clone());
    let name = decode.claims.user_name;
    let password = decode.claims.user_password;


    // let user = _User {
    //     user_id: 1i32,
    //     user_name: String::from("default username"),
    //     user_gender: String::from("default gender"),
    //     user_email: String::from("default@email.com"),
    //     user_password: String::from("default password"),
    //     create_date: SystemTime::now(),
    //     user_profile: Some(String::from("default profile")),
    //     user_role: Some(String::from("default role")),
    //     phone_number: String::from("default number")
    // };

    if(find_result == Find::Found) {
        let user = users.filter(user_name.like(name))
        .filter(user_password.like(password))
        .get_result(&establish_connection())
        .unwrap();
        println!("true in back-end: {:#?}", user);
        return Json(user);
    } else {
        let user = _User::new();
        // println!("false in back-end: {:#?}", user);
        return Json(user);
    }
}

use rocket::http::{Cookies, Cookie};
#[post("/test_login", data = "<log_info>")]
pub fn test_login(mut cookies: Cookies<'_>, log_info: Json<loginInfo>) -> String {
    use self::schema::users::dsl::*;

    let connection = establish_connection();

    let user_list = get_user(&connection);
    let mut string = String::new();

    for _user in user_list.iter() {
        if(_user.user_name.trim() == log_info.user_name.trim()) {
            if(_user.user_password.trim() == log_info.user_password.trim()) {
                let role = _user.user_role.as_ref().unwrap();
                string = generate_token(_user.user_name.to_string(),   
                                        _user.user_password.to_string(), 
                                        role.to_string());
                cookies.add(Cookie::new("token", string.clone()));
                // println!("{:#?}", cookies);
                break;
            } else {
                string = format!("Log in Failed");  
            }
        } else {
            string = format!("Log in Failed");
        }
    }
    return string;
}

// #[get("/a")]
// pub fn a() -> String {
//     String::fr
// }



#[get("/userData1")]
pub fn userData1(cookies: Cookies<'_>) -> Json<_User> {
    use self::schema::users::dsl::{users, user_name, user_password};
    println!("{:#?}", cookies);
    let token = cookies.get("token").unwrap().value();
    println!("token: {}", token.clone());


    let find_result = filter_user(token.clone().to_string());

    let decode = decode_token(token.clone().to_string());
    let name = decode.claims.user_name;
    let password = decode.claims.user_password;

    if(find_result == Find::Found) {
        let user = users.filter(user_name.like(name))
        .filter(user_password.like(password))
        .get_result(&establish_connection())
        .unwrap();
        println!("true in back-end: {:#?}", user);
        return Json(user);
    } else {
        let user = _User::new();
        return Json(user);
    }
}

// use rocket::Request;
use self::models::ApiKey;
#[get("/userData2")]
pub fn userData2(key: ApiKey) -> Json<_User>{
    use self::schema::users::dsl::{users, user_name, user_password};
    
    let token = key.into_inner();

    println!("token: {}", token);


    let find_result = filter_user(token.clone().to_string());

    let decode = decode_token(token.clone().to_string());
    let name = decode.claims.user_name;
    let password = decode.claims.user_password;

    if(find_result == Find::Found) {
        let user = users.filter(user_name.like(name))
        .filter(user_password.like(password))
        .get_result(&establish_connection())
        .unwrap();
        println!("true in back-end: {:#?}", user);
        return Json(user);
    } else {
        let user = _User::new();
        return Json(user);
    }
}



use std::time::{SystemTime};
extern crate jsonwebtoken;
use jsonwebtoken::{Header, decode, Validation};
extern crate chrono;
use chrono::{Utc, DateTime, Duration};
pub use self::token::{Claims, generate_token};


#[get("/admin")]
pub fn admin_dashboard() -> String {
    format!("Admin dashboard")
}

#[get("/user")]
pub fn user_dashboard() -> String {
    format!("User dashboard")
}

#[get("/error")]
pub fn error_dashboard() -> String {
    format!("Error dashboard")
}

#[get("/delete_success")]
pub fn delete_sucess() -> String {
    format!("Self Destoy completed!!!")
}

use rocket::response::Redirect;
use token::decode_token;
#[post("/checking", data = "<token_>")]
pub fn check_user_role(token_: Json<Token>) -> Redirect {
    //I don't why it has "token=a;sldkfja;sldjfa;lsdf" 
    //when i try to send token from postman so i need to delete some string before
    //token to make it become ValidToken
    // let dec_res = jsonwebtoken::decode::<Claims>(&ok_token, "secret".as_ref(), &Validation::default()).unwrap();
    
    let dec_res = decode_token(token_.token.clone());
    let user_role = dec_res.claims.user_role;
    println!("user role = {}", user_role);

    if(user_role == "Admin".to_string()) {
        //redirect to admin dashboard
        Redirect::to(uri!(admin_dashboard))
    } else if (user_role == "User".to_string()) {
        //redirect to user dasboard
        Redirect::to(uri!(user_dashboard))
    } else {
        //user role conflict
        Redirect::to(uri!(error_dashboard))
    }
}


pub mod schema;
pub mod models;
pub mod token;
