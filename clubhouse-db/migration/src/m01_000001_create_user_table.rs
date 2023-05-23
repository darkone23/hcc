use sea_orm::Statement;

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m01_000001_create_user_table"
    }
}

/*
async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    let sql = "CREATE TABLE `cake` ( `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY, `name` varchar(255) NOT NULL )";
    let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
    manager.get_connection().execute(stmt).await.map(|_| ())

    */

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // we use hash as companion for our unique / index searchable keys
        let sql = "\
        CREATE TABLE user_email_password ( \
            id serial NOT NULL PRIMARY KEY, \
            email varchar NOT NULL, \
            email_hash varchar NOT NULL UNIQUE, \
            password varchar NOT NULL, \
            active boolean NOT NULL \
        )";

        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = "DROP TABLE user_email_password";
        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }
}
