use rocket::{Request, Data, Outcome::*};
use rocket::data::{self, FromDataSimple};

use std::time::SystemTime;

use serde::{Serialize, Deserialize};


use diesel::sql_types::{Integer, Varchar, Timestamp};
#[derive(Serialize, Queryable, QueryableByName,  Debug)]
#[table_name="players"]
pub struct PlayerQue {
    #[sql_type="Integer"]
    pub id: i32,
    #[sql_type="Varchar"]
    pub playername: String,
    #[sql_type="Integer"]
    pub score: i32,
    #[sql_type="Timestamp"]
    pub playdate: SystemTime,
    #[sql_type="Varchar"]
    pub email: String
}

// use rand::Rng;
// use rand::distributions::{Distribution, Standard};
// impl Distribution<PlayerQue> for Standard {
//     fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PlayerQue {
//         PlayerQue {
//             id:         rng.gen(),
//             // playername: rng.gen(),
//             // score:      rng.gen(),
//             // playdate:   rng.gen(),
//             // email:      rng.gen()
//         }
//     }
// }

use super::schema::players;
#[derive(Insertable, Queryable, Debug, Serialize, Deserialize)]
#[table_name="players"]
pub struct Player {
    pub playername: String,
    pub score: i32,
    // pub playdate: SystemTime,
    pub email: String
}

impl FromDataSimple for Player {
    type Error = String;

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, String> {
        // let now = SystemTime::now();
        
        let new_player = Player {
            playername:     String::from("player default name"),
            score:          0i32,
            // playdate:       now,
            email:          String::from("player default email")
        };

        Success(new_player)
    }
}


#[derive(Serialize, Deserialize)]
pub struct PlayResult {
    pub score: i32
}

impl FromDataSimple for PlayResult {
    type Error = String;

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, String> {
        // let now = SystemTime::now();
        
        let new_result = PlayResult {
            score:          0i32,
        };

        Success(new_result)
    }
}

#[derive(QueryableByName, Debug)]
#[table_name="questions"]
pub struct QADB {
    // pub serial_id:           i32,
    pub question_id:         i32,
    pub question:            String,    
    pub correct_answer:      String,
    pub incorrect_answer1:   String,
    pub incorrect_answer2:   String,
    pub incorrect_answer3:   String,
    pub incorrect_answer4:   String,
    pub incorrect_answer5:   String
}

use super::schema::questions;
#[derive(Debug, Insertable)]
#[table_name="questions"]
pub struct QandA {
    // pub question_id:         i32,
    pub question:            String,
    pub correct_answer:      String,
    pub incorrect_answer1:   String,
    pub incorrect_answer2:   String,
    pub incorrect_answer3:   String,
    pub incorrect_answer4:   String,
    pub incorrect_answer5:   String
}

#[derive(Serialize, Debug)]
pub struct Question {
    pub question_id:         i32,
    pub question:            String,
    pub correct_answer:      String,
    pub incorrect_answer1:   String,
    pub incorrect_answer2:   String,
    pub incorrect_answer3:   String
}

#[derive(Serialize, Debug)]
pub struct Question1 {
    pub question:       String,
    pub optionA:        String,
    pub optionB:        String,
    pub optionC:        String,
    pub optionD:        String,
    pub answer:         String
}