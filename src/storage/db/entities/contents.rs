use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "contents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub collection_id: i64,
    pub slug: String,
    pub title: String,
    pub status: String,
    pub schema_id: Option<String>,
    pub draft_snapshot_key: Option<String>,
    pub latest_snapshot_key: Option<String>,
    pub latest_version: i32,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub archived_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::collections::Entity",
        from = "Column::CollectionId",
        to = "super::collections::Column::Id",
        on_delete = "Cascade"
    )]
    Collection,
    #[sea_orm(has_many = "super::content_versions::Entity")]
    ContentVersions,
    #[sea_orm(has_many = "super::nodes::Entity")]
    Nodes,
}

impl Related<super::collections::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Collection.def()
    }
}

impl Related<super::content_versions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ContentVersions.def()
    }
}

impl Related<super::nodes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nodes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
