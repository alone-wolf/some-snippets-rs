use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "history_nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub history_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: i32,
    pub order_index:i32,
    pub alias_name: Option<String>,
    pub created_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
