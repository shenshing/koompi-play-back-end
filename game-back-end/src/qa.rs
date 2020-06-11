// #![feature(proc_macro_hygiene, decl_macro)]

// #[macro_use] extern crate rocket;

extern crate serde;
use serde::{Serialize, Deserialize};

use rocket_contrib::json::Json;
#[derive(Deserialize, Serialize)]
pub struct QA {
    pub question: String,
    pub answer: String,
}

// #[get("/question")]
// pub fn question() -> Json<Vec<QA>> {
//     let question1 = QA {
//         question: String::from("Answer the first question"),
//         answer: String::from("Answer1"),
//     };

//     let question2 = QA {
//         question: String::from("Answer the second question"),
//         answer: String::from("Answer1"),
//     };

//     let question3 = QA {
//         question: String::from("Answer the third question"),
//         answer: String::from("Answer1"),
//     };

//     let question4 = QA {
//         question: String::from("Answer the fourth question"),
//         answer: String::from("Answer1"),
//     };

//     let question5 = QA {
//         question: String::from("Answer the fifth question"),
//         answer: String::from("Answer1"),
//     };


//     let mut vec_question: Vec<QA> = Vec::new();
//     vec_question.push(question1);
//     vec_question.push(question2);
//     vec_question.push(question3);
//     vec_question.push(question4);
//     vec_question.push(question5);
//     Json(vec_question)
// }




// use std::time::SystemTime;
// use rocket::{Request, Data, Outcome::*};
// use rocket::data::{self, FromDataSimple};

// pub struct Datetime {
//     datetime: std::time::SystemTime,
// }

// impl FromDataSimple for Datetime {
//     type Error = String;

//     fn from_data(req: &Request, data: Data) -> data::Outcome<Self, String> {
//         let now = SystemTime::now();
        
//         let new_date = Datetime {
//             datetime: now
//         };

//         Success(new_date)
//     }
// }

// #[post("/date", data = "<date>")]
// pub fn test_time(date: Datetime) -> &'static str {
//     &"This is date time"
// }




use std::fs;
use crate::models::QandA;
use diesel::dsl::*;
use crate::diesel::RunQueryDsl;
use crate::establish_connection;

pub fn save_question_to_db() {

    use crate::schema::questions::dsl::*;

    let content = fs::read_to_string("/home/koompi/Desktop/play.txt")
        .expect("open file error");

    let mut vec_question: Vec<QandA> = Vec::new();

    for line in content.lines() {
        // println!("{}", line);
        let vec: Vec<&str> = line.split(",\t").collect();
        // println!("{:#?}", vec);
        // println!("vec_len: {}", vec.len());
        let q_a = QandA {
            // question_id:        (vec_question.len() + 1usize) as i32,
            question:           vec[0].to_string(),
            correct_answer:     vec[1].to_string(),
            incorrect_answer1:  vec[2].to_string(),
            incorrect_answer2:  vec[3].to_string(),
            incorrect_answer3:  vec[4].to_string(),
            incorrect_answer4:  vec[5].to_string(),
            incorrect_answer5:  vec[6].to_string()
        };
        vec_question.push(q_a);
    }
    // println!("{}", vec_question.len());
    // println!("{:#?}", vec_question);
    // println!("{:#?}", content);

    let insert_result = insert_into(questions)
        .values(&vec_question)
        .on_conflict_do_nothing()
        .execute(&establish_connection());

    // let insert_result = insert_or_ignore_into(questions)
    //     .values(&vec_question)
    //     .execute(&establish_connection());

    match insert_result {
        Ok(_) => println!("Insert question successfull"),
        Err(err) => println!("Insert question error: {}", err)  
    }

    // println!("Hello World");
}

//random answer
use crate::models::Question;
use crate::models::Question1;
use rand::seq::SliceRandom;
use rand::thread_rng;
pub fn random_answer(question: Vec<QADB>) -> Vec<Question1> {
    
    let mut formal_question: Vec<Question1> = Vec::new();

    for q in question.iter() {
        
        let mut incorrect_answer_vec: Vec<&str> = Vec::new();
        incorrect_answer_vec.push(&q.incorrect_answer1);
        incorrect_answer_vec.push(&q.incorrect_answer2);
        incorrect_answer_vec.push(&q.incorrect_answer3);
        incorrect_answer_vec.push(&q.incorrect_answer4);
        incorrect_answer_vec.push(&q.incorrect_answer5);

        let mut final_answer: Vec<_> = incorrect_answer_vec    
            .choose_multiple(&mut rand::thread_rng(), 3)
            .collect();

        // println!("final_answer: {:#?}", final_answer);

        // let samples = vec!["hi", "this", "is", "a", "test!"];
        // let sample: Vec<_> = samples
        //     .choose_multiple(&mut rand::thread_rng(), 1)
        //     .collect();
        // println!("{:?}", sample);

        // let quest = Question {
        //     question_id:        q.question_id,
        //     question:           q.question.clone(),
        //     correct_answer:     q.correct_answer.clone(),
        //     incorrect_answer1:  final_answer[0].to_string(),
        //     incorrect_answer2:  final_answer[1].to_string(),
        //     incorrect_answer3:  final_answer[2].to_string()

        // };

        // println!("{:#?}", final_answer);
        let correct_answer: &str = &q.correct_answer.clone()[..];
        final_answer.push(&&correct_answer);
        let mut rng = thread_rng();
        final_answer.shuffle(&mut rng);


        let quest = Question1 {
            question:       q.question.clone(),
            // optionA:        q.correct_answer.clone(),
            optionA:        final_answer[0].to_string(),
            optionB:        final_answer[1].to_string(),
            optionC:        final_answer[2].to_string(),
            optionD:        final_answer[3].to_string(),
            answer:         q.correct_answer.clone(),
        };

        formal_question.push(quest);
    }

    // value
    // return formal_question;
    // println!("{:#?}", final_answer);
    return formal_question;
}

//random question
use crate::models::QADB;
pub fn random_question() -> Result<Vec<QADB>, diesel::result::Error> {
    let statement = format!("Select * From questions Order By random() limit 5;");

    let result = sql_query(statement)
        .get_results(&establish_connection());

    match result {
        Ok(ok) => return Ok(ok),
        Err(err) => return Err(err),
    }
    return result;
}


#[get("/question")]
pub fn question_for_front_end() -> Json<Vec<Question1>> {
    return Json(random_answer(random_question().unwrap()));
}