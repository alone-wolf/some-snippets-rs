use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Contents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Contents::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Contents::CollectionId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Contents::Slug).string().not_null())
                    .col(ColumnDef::new(Contents::Title).string().not_null())
                    .col(ColumnDef::new(Contents::Status).string().not_null())
                    .col(ColumnDef::new(Contents::SchemaId).string())
                    .col(ColumnDef::new(Contents::DraftSnapshotKey).string())
                    .col(ColumnDef::new(Contents::LatestSnapshotKey).string())
                    .col(
                        ColumnDef::new(Contents::LatestVersion)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Contents::CreatedBy).string().not_null())
                    .col(ColumnDef::new(Contents::UpdatedBy).string().not_null())
                    .col(
                        ColumnDef::new(Contents::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Contents::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Contents::ArchivedAt).timestamp())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-contents-collection-id")
                            .from(Contents::Table, Contents::CollectionId)
                            .to(Collections::Table, Collections::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-contents-collection-slug-unique")
                    .table(Contents::Table)
                    .col(Contents::CollectionId)
                    .col(Contents::Slug)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx-contents-collection-slug-unique")
                    .table(Contents::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Contents::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Contents {
    Table,
    Id,
    CollectionId,
    Slug,
    Title,
    Status,
    SchemaId,
    DraftSnapshotKey,
    LatestSnapshotKey,
    LatestVersion,
    CreatedBy,
    UpdatedBy,
    CreatedAt,
    UpdatedAt,
    ArchivedAt,
}

#[derive(DeriveIden)]
enum Collections {
    Table,
    Id,
}
