use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Collections::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Collections::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Collections::Slug).string().not_null())
                    .col(ColumnDef::new(Collections::Name).string().not_null())
                    .col(ColumnDef::new(Collections::Description).text())
                    .col(ColumnDef::new(Collections::Visibility).string().not_null())
                    .col(ColumnDef::new(Collections::OwnerId).string().not_null())
                    .col(ColumnDef::new(Collections::ConfigJson).json())
                    .col(
                        ColumnDef::new(Collections::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Collections::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Collections::ArchivedAt).timestamp())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-collections-slug-unique")
                    .table(Collections::Table)
                    .col(Collections::Slug)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx-collections-slug-unique")
                    .table(Collections::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Collections::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Collections {
    Table,
    Id,
    Slug,
    Name,
    Description,
    Visibility,
    OwnerId,
    ConfigJson,
    CreatedAt,
    UpdatedAt,
    ArchivedAt,
}
