table! {
    date_time (user_id) {
        user_id -> Int4,
        create_date -> Timestamp,
    }
}

table! {
    examples (id) {
        id -> Int4,
        created_at -> Timestamp,
        updated_at -> Nullable<Timestamp>,
    }
}

table! {
    players (id) {
        id -> Int4,
        playername -> Varchar,
        score -> Int4,
        playdate -> Timestamp,
        email -> Varchar,
    }
}

table! {
    users (user_id) {
        user_id -> Int4,
        user_name -> Varchar,
        user_gender -> Varchar,
        user_email -> Varchar,
        user_password -> Varchar,
        create_date -> Timestamp,
        user_profile -> Nullable<Varchar>,
        user_role -> Nullable<Varchar>,
        phone_number -> Varchar,
    }
}

allow_tables_to_appear_in_same_query!(
    date_time,
    examples,
    players,
    users,
);
