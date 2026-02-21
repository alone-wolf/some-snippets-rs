#![allow(dead_code)]

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "history_nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub history_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: i32,
    pub order_index: i32,
    pub alias_name: Option<String>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
