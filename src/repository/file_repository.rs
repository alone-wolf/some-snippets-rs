use crate::entity::{FileActiveModel, FileModel};
use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr};

pub(crate) struct FileRepository;

impl FileRepository {
    pub(crate) async fn insert<C>(db: &C, active_model: FileActiveModel) -> Result<FileModel, DbErr>
    where
        C: ConnectionTrait,
    {
        active_model.insert(db).await
    }
}
