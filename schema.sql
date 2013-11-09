drop table if exists users;
create table users (
     "id" integer NOT NULL PRIMARY KEY,
     "name" varchar(255) NOT NULL,
     "email" varchar(255) NOT NULL,
     "googleId" varchar(40) NOT NULL,
     "refreshToken" varchar(45) NOT NULL,
     "created_at" integer NOT NULL
);

/*
create table activities (
     "id" integer NOT NULL PRIMARY KEY,
     "category" varchar(255) NOT NULL,
     "title" varchar(255) NOT NULL,
     "user_id" varchar(40) NOT NULL,
     "created_at" integer NOT NULL,
     "updated_at" integer NOT NULL
);
*/

