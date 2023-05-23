use sea_orm::Statement;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m01_000002_create_user_attributes_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = "\
        CREATE TABLE user_attributes ( \
            id serial NOT NULL PRIMARY KEY, \
            uid integer NOT NULL REFERENCES user_email_password (id), \
            display varchar NOT NULL UNIQUE, \
            created_at timestamp with time zone NOT NULL, \
            last_login timestamp with time zone NULL, \
            last_updated timestamp with time zone NOT NULL DEFAULT current_timestamp,  \
            settings varchar NOT NULL \
        )";
        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = "DROP TABLE user_attributes";
        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }
}
