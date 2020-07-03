// #![feature(proc_macro_hygiene, decl_macro)]

// #[macro_use] extern crate rocket;

extern crate serde;
use serde::{Serialize, Deserialize};

use rocket_contrib::json::Json;


use std::fs;
use crate::models::QandA;
use diesel::dsl::*;
use crate::diesel::RunQueryDsl;
use crate::establish_connection;

pub fn save_question_to_db() {

    use crate::schema::questions::dsl::*;

    // let content = fs::read_to_string("/home/koompi/Desktop/play1.txt")
    //     .expect("open file error");

    let content = fs::read_to_string("./play.txt")
        .expect("open file error");

    let mut vec_question: Vec<QandA> = Vec::new();

    for line in content.lines() {
        let vec: Vec<&str> = line.split(",\t").collect();
        let q_a = QandA {
            question:           vec[0].to_string(),
            correct_answer:     vec[1].to_string(),
            incorrect_answer1:  vec[2].to_string(),
            incorrect_answer2:  vec[3].to_string(),
            incorrect_answer3:  vec[4].to_string(),
            incorrect_answer4:  vec[5].to_string(),
            incorrect_answer5:  vec[6].to_string(),
            category:           vec[7].to_string(),
            // category:           String::from("a")
        };
        vec_question.push(q_a);
        println!("{}", vec[7]);
        // println!("{}", line);
    }

    // println!("{:#?}", vec_question);

    let insert_result = insert_into(questions)
        .values(&vec_question)
        .on_conflict_do_nothing()
        .execute(&establish_connection());

    match insert_result {
        Ok(_) => println!("Insert question successfull"),
        Err(err) => println!("Insert question error: {}", err)  
    }

}

//random answer
use crate::models::{Question};
use rand::seq::SliceRandom;
use rand::thread_rng;
pub fn random_answer(question: Vec<QADB>) -> Vec<Question> {
    
    let mut formal_question: Vec<Question> = Vec::new();

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

        let correct_answer: &str = &q.correct_answer.clone()[..];
        final_answer.push(&&correct_answer);
        let mut rng = thread_rng();
        final_answer.shuffle(&mut rng);


        let quest = Question {
            question:       q.question.clone(),
            optionA:        final_answer[0].to_string(),
            optionB:        final_answer[1].to_string(),
            optionC:        final_answer[2].to_string(),
            optionD:        final_answer[3].to_string(),
            answer:         q.correct_answer.clone(),
        };

        formal_question.push(quest);
    }

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

pub fn random_question_category(cate: String) -> Result<Vec<QADB>, diesel::result::Error> {
    let statement = format!("Select * From questions Where category='{}' Order By random() limit 5;", cate);

    let result = sql_query(statement)
        .get_results(&establish_connection());

    match result {
        Ok(ok) => return Ok(ok),
        Err(err) => return Err(err),
    }
    return result;
}


#[get("/general-question")]
pub fn general_question() -> Json<Vec<Question>> {
    return Json(random_answer(random_question().unwrap()));
}

#[get("/history-question")]
pub fn history_question() -> Json<Vec<Question>> {
    let cate = String::from("history");
    return Json(random_answer(random_question_category(cate).unwrap()));
}

#[get("/science-question")]
pub fn science_question() -> Json<Vec<Question>> {
    let cate = String::from("science");
    return Json(random_answer(random_question_category(cate).unwrap()));
}

#[get("/calculating-question")]
pub fn calculating_question() -> Json<Vec<Question>> {
    let cate = String::from("calculating");
    return Json(random_answer(random_question_category(cate).unwrap()));
}