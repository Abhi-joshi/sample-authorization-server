CREATE TABLE if not exists enduser (
                                   enduser_id bigserial NOT NULL,
                                   username varchar(255) NOT NULL,
                                   "password" varchar(255) NOT NULL,
                                   email varchar(255) NOT NULL,
                                   enabled bool NOT NULL,
                                   CONSTRAINT enduser_email_key UNIQUE (email),
                                   CONSTRAINT enduser_pkey PRIMARY KEY (enduser_id),
                                   CONSTRAINT enduser_username_key UNIQUE (username)
);

CREATE TABLE if not exists enduser_role (
                                        enduser_role_id bigserial NOT NULL,
                                        username varchar(255) NOT NULL,
                                        "role" varchar(255) NOT NULL,
                                        enduser_id int8 NOT NULL,
                                        CONSTRAINT enduser_role_pkey PRIMARY KEY (enduser_role_id)
);

CREATE TABLE if not exists oauth2_authorization (
                                                id varchar(100) NOT NULL,
                                                registered_client_id varchar(100) NOT NULL,
                                                principal_name varchar(200) NOT NULL,
                                                authorization_grant_type varchar(100) NOT NULL,
                                                authorized_scopes varchar(1000) NULL DEFAULT NULL::character varying,
                                                "attributes" text NULL,
                                                state varchar(500) NULL DEFAULT NULL::character varying,
                                                authorization_code_value text NULL,
                                                authorization_code_issued_at timestamp NULL,
                                                authorization_code_expires_at timestamp NULL,
                                                authorization_code_metadata text NULL,
                                                access_token_value text NULL,
                                                access_token_issued_at timestamp NULL,
                                                access_token_expires_at timestamp NULL,
                                                access_token_metadata text NULL,
                                                access_token_type varchar(100) NULL DEFAULT NULL::character varying,
                                                access_token_scopes varchar(1000) NULL DEFAULT NULL::character varying,
                                                oidc_id_token_value text NULL,
                                                oidc_id_token_issued_at timestamp NULL,
                                                oidc_id_token_expires_at timestamp NULL,
                                                oidc_id_token_metadata text NULL,
                                                refresh_token_value text NULL,
                                                refresh_token_issued_at timestamp NULL,
                                                refresh_token_expires_at timestamp NULL,
                                                refresh_token_metadata text NULL,
                                                user_code_value text NULL,
                                                user_code_issued_at timestamp NULL,
                                                user_code_expires_at timestamp NULL,
                                                user_code_metadata text NULL,
                                                device_code_value text NULL,
                                                device_code_issued_at timestamp NULL,
                                                device_code_expires_at timestamp NULL,
                                                device_code_metadata text NULL,
                                                CONSTRAINT oauth2_authorization_pkey PRIMARY KEY (id)
);

CREATE TABLE if not exists oauth2_authorization_consent (
                                                        registered_client_id varchar(100) NOT NULL,
                                                        principal_name varchar(200) NOT NULL,
                                                        authorities varchar(1000) NOT NULL,
                                                        CONSTRAINT oauth2_authorization_consent_pkey PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE if not exists oauth2_registered_client (
                                                    id varchar(100) NOT NULL,
                                                    client_id varchar(100) NOT NULL,
                                                    client_id_issued_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                    client_secret varchar(200) NULL DEFAULT NULL::character varying,
                                                    client_secret_expires_at timestamp NULL,
                                                    client_name varchar(200) NOT NULL,
                                                    client_authentication_methods varchar(1000) NOT NULL,
                                                    authorization_grant_types varchar(1000) NOT NULL,
                                                    redirect_uris varchar(1000) NULL DEFAULT NULL::character varying,
                                                    post_logout_redirect_uris varchar(1000) NULL DEFAULT NULL::character varying,
                                                    scopes varchar(1000) NOT NULL,
                                                    client_settings varchar(2000) NOT NULL,
                                                    token_settings varchar(2000) NOT NULL,
                                                    CONSTRAINT oauth2_registered_client_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE if not exists enduser_seq
    INCREMENT BY 50
    MINVALUE 1
    MAXVALUE 9223372036854775807
    START 10
    CACHE 1
    NO CYCLE;