use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "nodes")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub content_id: i64,
    pub uuid: String,
    pub version: i32,
    pub kind: String,
    pub lifecycle_state: String,
    pub text_content: Option<String>,
    pub prev_node_id: Option<i64>,
    pub meta_json: Option<Json>,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub deleted_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::contents::Entity",
        from = "Column::ContentId",
        to = "super::contents::Column::Id",
        on_delete = "Cascade"
    )]
    Content,
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::PrevNodeId",
        to = "Column::Id",
        on_delete = "SetNull"
    )]
    PreviousNode,
    #[sea_orm(has_one = "super::file_metadata::Entity")]
    FileMetadata,
}

impl Related<super::contents::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Content.def()
    }
}

impl Related<super::file_metadata::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FileMetadata.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
