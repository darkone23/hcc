# Running Migrator CLI

you will need to make sure you have the proper database ENV variable set

some stuff for the postgres instance that should be running somewhere:

for demo purposes:

nix/direnv should have installd `sea` for you
you should have your hcc-server secrets set up first:

`which sea`

`DATABASE_URL=$HCC_SQL_CONNECTION_URL touch $HCC_SQL_CONNECTION_URL && sea migrate`

to code-generate entities into the server project:

`sea generate entity -o $HCC_SERVER/domain/src/sea_orm/entities/`