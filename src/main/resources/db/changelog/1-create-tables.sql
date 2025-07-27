CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       username VARCHAR(64) NOT NULL UNIQUE,
                       email VARCHAR(128) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
                                          user_id BIGINT    NOT NULL,
                                          roles   VARCHAR(50) NOT NULL
);

ALTER TABLE user_roles
    ADD CONSTRAINT fk_user_roles_user
        FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE;

ALTER TABLE user_roles
    ADD CONSTRAINT pk_user_roles PRIMARY KEY (user_id, roles);


CREATE SEQUENCE IF NOT EXISTS users_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE users_seq
    OWNED BY users.id;

ALTER TABLE users
    ALTER COLUMN id
        SET DEFAULT nextval('users_seq');