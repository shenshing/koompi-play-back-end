-- Your SQL goes here
Create Table player (
    id Serial Primary Key,
    playername Varchar(50) Not Null,
    score Integer Not Null,
    playdate Timestamp Not Null Default Current_Timestamp,
    email Varchar(50) Not Null,
    quiz_category Varchar(20) Not Null Default 'general-quiz'
)