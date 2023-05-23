use sea_orm::Statement;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m01_000003_create_media_node_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = "\
        CREATE TABLE media_node ( \
            id serial NOT NULL PRIMARY KEY, \
            media_slug varchar NOT NULL UNIQUE, \
            medium_type integer NOT NULL, \
            sort_key integer NOT NULL, \
            published boolean NOT NULL, \
            archived boolean NOT NULL, \
            created timestamp WITH TIME ZONE NOT NULL, \
            updated timestamp WITH TIME ZONE NOT NULL DEFAULT current_timestamp,  \
            template varchar NOT NULL, \
            context varchar NOT NULL \
        )";
        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = "DROP TABLE media_node";
        let stmt = Statement::from_string(manager.get_database_backend(), sql.to_owned());
        manager.get_connection().execute(stmt).await.map(|_| ())
    }
}
