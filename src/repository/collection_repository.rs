use crate::entity::{CollectionColumn, CollectionEntity, CollectionModel};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

pub(crate) struct CollectionRepository;

impl CollectionRepository {
    pub(crate) async fn find_json_by_key<C>(
        db: &C,
        key: &str,
    ) -> Result<Option<serde_json::Value>, DbErr>
    where
        C: ConnectionTrait,
    {
        CollectionEntity::find()
            .filter(CollectionColumn::Key.eq(key))
            .into_json()
            .one(db)
            .await
    }

    pub(crate) async fn find_model_by_key<C>(
        db: &C,
        key: &str,
    ) -> Result<Option<CollectionModel>, DbErr>
    where
        C: ConnectionTrait,
    {
        CollectionEntity::find()
            .filter(CollectionColumn::Key.eq(key))
            .one(db)
            .await
    }
}
