use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "snippet_tags")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub snippet_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub tag_id: i32,
    pub created_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
