-- Your SQL goes here
Create Table questions (
    question_id Serial Primary Key,
    question Varchar(100) Unique Not Null,
    correct_answer Varchar(50) Not Null,
    incorrect_answer1 Varchar(50) Not Null,
    incorrect_answer2 Varchar(50) Not Null,
    incorrect_answer3 Varchar(50) Not Null,
    incorrect_answer4 Varchar(50) Not Null,
    incorrect_answer5 Varchar(50) Not Null  
)