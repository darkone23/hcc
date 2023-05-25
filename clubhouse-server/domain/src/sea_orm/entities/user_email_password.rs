//! `SeaORM` Entity. Generated by sea-orm-codegen 0.11.3

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "user_email_password")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub email: String,
    pub email_hash: String,
    pub password: String,
    pub active: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::user_attributes::Entity")]
    UserAttributes,
}

impl Related<super::user_attributes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserAttributes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
