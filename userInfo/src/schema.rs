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
