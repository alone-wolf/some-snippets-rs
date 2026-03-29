use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ContentVersions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ContentVersions::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ContentVersions::ContentId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ContentVersions::Version)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ContentVersions::Label).string())
                    .col(
                        ColumnDef::new(ContentVersions::SnapshotKey)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ContentVersions::SnapshotChecksum)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ContentVersions::CreatedBy)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ContentVersions::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(ContentVersions::MetaJson).json())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-content-versions-content-id")
                            .from(ContentVersions::Table, ContentVersions::ContentId)
                            .to(Contents::Table, Contents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-content-versions-content-version-unique")
                    .table(ContentVersions::Table)
                    .col(ContentVersions::ContentId)
                    .col(ContentVersions::Version)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx-content-versions-content-version-unique")
                    .table(ContentVersions::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ContentVersions::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum ContentVersions {
    Table,
    Id,
    ContentId,
    Version,
    Label,
    SnapshotKey,
    SnapshotChecksum,
    CreatedBy,
    CreatedAt,
    MetaJson,
}

#[derive(DeriveIden)]
enum Contents {
    Table,
    Id,
}
