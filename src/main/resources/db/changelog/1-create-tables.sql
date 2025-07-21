CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       username VARCHAR(64) NOT NULL UNIQUE,
                       email VARCHAR(128) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE user_roles (
                            user_id BIGINT NOT NULL,
                            role VARCHAR(32) NOT NULL,
                            CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
