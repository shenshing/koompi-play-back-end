
use rocket::{Request, Data, Outcome::*};
use rocket::data::{self, FromDataSimple};

use crate::establish_connection;




/* FUNCTION PART */
#[derive(Debug)]
pub enum Save_Result {
    save,
    unsave,
}

use diesel::prelude::*;
use diesel::pg::PgConnection;
pub fn save_user_to_db(conn: &PgConnection, player: Player) -> Save_Result {
    use crate::schema::player;
    
    println!("inside save_to_db: {:#?}", player);
    let new_player = Player {
        playername: player.playername,
        score: player.score,
        email: player.email,
        quiz_category: player.quiz_category
    };

    let insert_result = diesel::insert_into(player::table)
        .values(&new_player)
        .execute(conn);
    println!("insert result: {:#?}", insert_result);
    match insert_result {
        Ok(_) => return Save_Result::save,
        Err(err) => return Save_Result::unsave,
    }
}

use crate::models::PlayerQue;
pub fn playerque_to_player(playerque: PlayerQue, player: Player) -> Player {
    return Player {
        playername: playerque.playername,
        score:      playerque.score,
        email:      playerque.email,
        quiz_category: playerque.quiz_category
    }
}


/* ENDPOINT PART */
//an endpoint for get_player_info

use userInfo::models::ApiKey;
use userInfo::token::{decode_token};
use userInfo::get_user_by_email;

use rocket_contrib::json::Json;
use crate::models::{Player, PlayResult};
#[post("/play_info", data="<p_result>")]
pub fn save_player_data(key: ApiKey, p_result: Json<PlayResult>) -> String {
    println!("inside play_info");

    let token = key.into_inner();

    let claim = decode_token(token.clone().to_string());

    let email = claim.claims.user_email;

    let user = get_user_by_email(email).unwrap();

    let conn = establish_connection();
    let p = p_result.into_inner();

    let player_save = Player {
        playername: user.user_name,
        // score:      p_result.into_inner().score,
        score:      p.score,
        email:      user.user_email.unwrap(),
        // quiz_category: p_result.into_inner().result_category.clone()
        quiz_category: p.result_category
    };

    let save_res = save_user_to_db(&conn, player_save);

    let mut rt_st = String::new();

    match save_res {
        Save_Result::save => {
            rt_st = format!("successful save");
        },
        Save_Result::unsave => {
            rt_st = format!("unsuccessful save");
        }
    }
    
    return rt_st;
}
