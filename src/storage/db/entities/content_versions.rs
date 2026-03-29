use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "content_versions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub content_id: i64,
    pub version: i32,
    pub label: Option<String>,
    pub snapshot_key: String,
    pub snapshot_checksum: String,
    pub created_by: String,
    pub created_at: DateTimeUtc,
    pub meta_json: Option<Json>,
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
}

impl Related<super::contents::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Content.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
