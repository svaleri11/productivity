drop table if exists users;
create table users (
     "id" integer NOT NULL PRIMARY KEY,
     "name" varchar(255) NOT NULL,
     "googleId" varchar(40) NOT NULL
);

drop table if exists activities;
create table activities (
     "id" integer NOT NULL PRIMARY KEY,
     "category" varchar(255) NOT NULL,
     "title" varchar(255) NOT NULL,
     FOREIGN KEY(user_id) REFERENCES users(id),
     "user_id" varchar(40) NOT NULL,
     "created_at" integer NOT NULL,
     "updated_at" integer NOT NULL
);