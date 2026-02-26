use crate::entity::{CollectionActiveModel, CollectionColumn, CollectionEntity, CollectionModel};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde_json::Value;

pub(crate) struct CollectionRepository;

impl CollectionRepository {
    pub(crate) async fn list_records<C>(
        db: &C,
        page_size: u64,
        offset: u64,
    ) -> Result<Vec<Value>, DbErr>
    where
        C: ConnectionTrait,
    {
        CollectionEntity::find()
            .order_by_asc(CollectionColumn::Id)
            .limit(page_size)
            .offset(offset)
            .into_json()
            .all(db)
            .await
    }

    pub(crate) async fn find_json_by_key<C>(db: &C, key: &str) -> Result<Option<Value>, DbErr>
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

    pub(crate) async fn insert_and_reload<C>(db: &C, payload: Value) -> Result<Option<Value>, DbErr>
    where
        C: ConnectionTrait,
    {
        let active_model = CollectionActiveModel::from_json(payload)?;
        let insert_result = CollectionEntity::insert(active_model).exec(db).await?;

        CollectionEntity::find_by_id(insert_result.last_insert_id)
            .into_json()
            .one(db)
            .await
    }

    pub(crate) async fn update_from_json<C>(
        db: &C,
        existing: CollectionModel,
        payload: Value,
    ) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        let mut active_model = existing.into_active_model();
        active_model.set_from_json(payload)?;
        active_model.update(db).await?;
        Ok(())
    }

    pub(crate) async fn delete_by_id<C>(db: &C, id: i32) -> Result<u64, DbErr>
    where
        C: ConnectionTrait,
    {
        let result = CollectionEntity::delete_by_id(id).exec(db).await?;
        Ok(result.rows_affected)
    }
}
