set dotenv-load
set export

SQLITE_DB := `pwd` / "data/db.sqlite3"
DATABASE_URL := `echo $HCC_SQL_CONNECTION_URL`
CODEGEN_OUT := `pwd` / "clubhouse-server/domain/src/sea_orm/entities"

migrate:
	touch {{ SQLITE_DB }};
	cd clubhouse-db && nix develop --command sea migrate

codegen:
	cd clubhouse-db && nix develop --command sea generate entity -o {{ CODEGEN_OUT }}

setup-web:
	cd clubhouse-web && nix develop --command yarn install

build-web: setup-web
	cd clubhouse-web && nix develop --command yarn run build

build-clubhouse:
	cd clubhouse-server && nix develop --command cargo build --release

run:
	./clubhouse-server/target/release/clubhouse