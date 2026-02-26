use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    Iterable, PrimaryKeyToColumn, PrimaryKeyTrait, QueryOrder, QuerySelect, TryIntoModel,
};
use serde_json::Value;

pub(crate) struct ResourceRepository;

impl ResourceRepository {
    pub(crate) async fn list_records<E, C>(
        db: &C,
        page_size: u64,
        offset: u64,
    ) -> Result<Vec<Value>, DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    {
        let mut select = E::find();
        for primary_key in <E::PrimaryKey as Iterable>::iter() {
            select = select.order_by_asc(primary_key.into_column());
        }

        select
            .limit(page_size)
            .offset(offset)
            .into_json()
            .all(db)
            .await
    }

    pub(crate) async fn find_json_by_id<E, C>(db: &C, id: i32) -> Result<Option<Value>, DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).into_json().one(db).await
    }

    pub(crate) async fn find_model_by_id<E, C>(db: &C, id: i32) -> Result<Option<E::Model>, DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).one(db).await
    }

    pub(crate) async fn insert_from_json_and_reload<E, A, C>(
        db: &C,
        payload: Value,
    ) -> Result<Option<Value>, DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send,
        E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let active_model = A::from_json(payload)?;
        let insert_result = E::insert(active_model).exec(db).await?;

        E::find_by_id(insert_result.last_insert_id)
            .into_json()
            .one(db)
            .await
    }

    pub(crate) async fn update_from_json<E, A, C>(
        db: &C,
        existing: E::Model,
        payload: Value,
    ) -> Result<(), DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send,
        E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut active_model = existing.into_active_model();
        active_model.set_from_json(payload)?;
        active_model.update(db).await?;
        Ok(())
    }

    pub(crate) async fn delete_by_id<E, C>(db: &C, id: i32) -> Result<u64, DbErr>
    where
        E: EntityTrait,
        C: ConnectionTrait,
        i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        let result = E::delete_by_id(id).exec(db).await?;
        Ok(result.rows_affected)
    }
}
