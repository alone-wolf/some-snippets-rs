use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Nodes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Nodes::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Nodes::ContentId).big_integer().not_null())
                    .col(ColumnDef::new(Nodes::Uuid).string().not_null())
                    .col(
                        ColumnDef::new(Nodes::Version)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Nodes::Kind).string().not_null())
                    .col(ColumnDef::new(Nodes::LifecycleState).string().not_null())
                    .col(ColumnDef::new(Nodes::TextContent).text())
                    .col(ColumnDef::new(Nodes::PrevNodeId).big_integer())
                    .col(ColumnDef::new(Nodes::MetaJson).json())
                    .col(ColumnDef::new(Nodes::CreatedBy).string().not_null())
                    .col(ColumnDef::new(Nodes::UpdatedBy).string().not_null())
                    .col(
                        ColumnDef::new(Nodes::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Nodes::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Nodes::DeletedAt).timestamp())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-nodes-content-id")
                            .from(Nodes::Table, Nodes::ContentId)
                            .to(Contents::Table, Contents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-nodes-prev-node-id")
                            .from(Nodes::Table, Nodes::PrevNodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        for index in [
            Index::create()
                .name("idx-nodes-uuid-version-unique")
                .table(Nodes::Table)
                .col(Nodes::Uuid)
                .col(Nodes::Version)
                .unique()
                .to_owned(),
            Index::create()
                .name("idx-nodes-content-lifecycle")
                .table(Nodes::Table)
                .col(Nodes::ContentId)
                .col(Nodes::LifecycleState)
                .to_owned(),
            Index::create()
                .name("idx-nodes-content-kind")
                .table(Nodes::Table)
                .col(Nodes::ContentId)
                .col(Nodes::Kind)
                .to_owned(),
            Index::create()
                .name("idx-nodes-prev-node-id")
                .table(Nodes::Table)
                .col(Nodes::PrevNodeId)
                .to_owned(),
        ] {
            manager.create_index(index).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in [
            "idx-nodes-prev-node-id",
            "idx-nodes-content-kind",
            "idx-nodes-content-lifecycle",
            "idx-nodes-uuid-version-unique",
        ] {
            manager
                .drop_index(Index::drop().name(name).table(Nodes::Table).to_owned())
                .await?;
        }
        manager
            .drop_table(Table::drop().table(Nodes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    Id,
    ContentId,
    Uuid,
    Version,
    Kind,
    LifecycleState,
    TextContent,
    PrevNodeId,
    MetaJson,
    CreatedBy,
    UpdatedBy,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}

#[derive(DeriveIden)]
enum Contents {
    Table,
    Id,
}
