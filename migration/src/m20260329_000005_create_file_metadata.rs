use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(FileMetadata::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(FileMetadata::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(FileMetadata::NodeId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(FileMetadata::FileUuid).string().not_null())
                    .col(ColumnDef::new(FileMetadata::Bucket).string().not_null())
                    .col(ColumnDef::new(FileMetadata::ObjectKey).string().not_null())
                    .col(ColumnDef::new(FileMetadata::Filename).string().not_null())
                    .col(ColumnDef::new(FileMetadata::MimeType).string())
                    .col(
                        ColumnDef::new(FileMetadata::SizeBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(FileMetadata::Checksum).string())
                    .col(ColumnDef::new(FileMetadata::MetaJson).json())
                    .col(
                        ColumnDef::new(FileMetadata::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(FileMetadata::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-file-metadata-node-id")
                            .from(FileMetadata::Table, FileMetadata::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-file-metadata-node-id-unique")
                    .table(FileMetadata::Table)
                    .col(FileMetadata::NodeId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-file-metadata-file-uuid")
                    .table(FileMetadata::Table)
                    .col(FileMetadata::FileUuid)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx-file-metadata-file-uuid")
                    .table(FileMetadata::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx-file-metadata-node-id-unique")
                    .table(FileMetadata::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(FileMetadata::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum FileMetadata {
    Table,
    Id,
    NodeId,
    FileUuid,
    Bucket,
    ObjectKey,
    Filename,
    MimeType,
    SizeBytes,
    Checksum,
    MetaJson,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    Id,
}
