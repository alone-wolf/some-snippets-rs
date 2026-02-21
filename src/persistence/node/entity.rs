use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub kind: String, // text or file
    pub snippet_id: i32,
    pub text_id: Option<i32>,
    pub file_id: Option<i32>,
    pub meta_json: Option<String>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
