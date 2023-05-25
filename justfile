set dotenv-load
set export

PWD := `pwd`
SQLITE_DB :=  PWD / env_var("SQLITE_FILE") 

HCC_RSA_PRIVATE_KEY_PATH := PWD / env_var("SECRETS_DIR") / "jwtRS256.key"

HCC_RSA_PUBLIC_KEY_PATH := PWD / env_var("SECRETS_DIR") / "jwtRS256.key.pub"

HCC_CLIENT_DIST_DIR := PWD / env_var("CLIENT_DIR") / "dist/"

HCC_SQL_CONNECTION_URL := "sqlite:/" / SQLITE_DB

DATABASE_URL := HCC_SQL_CONNECTION_URL

CODEGEN_OUT := PWD / "clubhouse-server/domain/src/sea_orm/entities"

migrate:
	touch {{ SQLITE_DB }};
	cd clubhouse-db && nix develop --command sea migrate

codegen:
	cd clubhouse-db && nix develop --command sea generate entity -o {{ CODEGEN_OUT }}

setup-web:
	cd clubhouse-web && nix develop --command yarn install

build-web: setup-web
	cd clubhouse-web && nix develop --command yarn run build

build-server:
	cd clubhouse-server && nix develop --command cargo build --release

run-server:
	./clubhouse-server/target/release/clubhouse