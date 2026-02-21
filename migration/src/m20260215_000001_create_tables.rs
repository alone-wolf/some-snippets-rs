use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut tables = Vec::new();

        // Collections table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(Collection::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Collection::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Collection::Title).string().not_null())
                        .col(ColumnDef::new(Collection::Description).string())
                        .col(
                            ColumnDef::new(Collection::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(Collection::UpdatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(
                            Index::create()
                                .name("idx_collection_title")
                                .col(Collection::Title),
                        )
                        .index(
                            Index::create()
                                .name("idx_collection_created_at")
                                .col(Collection::CreatedAt),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // Texts table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(Text::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Text::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Text::Content).string().not_null())
                        .col(ColumnDef::new(Text::Kind).string().not_null())
                        .col(
                            ColumnDef::new(Text::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(Index::create().name("idx_text_kind").col(Text::Kind))
                        .to_owned(),
                )
                .await?,
        );

        // Files table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(File::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(File::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(File::StoragePath).string().not_null())
                        .col(ColumnDef::new(File::OriginalFilename).string().not_null())
                        .col(ColumnDef::new(File::MimeType).string())
                        .col(ColumnDef::new(File::ByteSize).integer())
                        .col(ColumnDef::new(File::Sha256).string())
                        .col(
                            ColumnDef::new(File::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(Index::create().name("idx_file_sha256").col(File::Sha256))
                        .to_owned(),
                )
                .await?,
        );

        // Tags table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(Tag::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Tag::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Tag::Name).string().not_null())
                        .col(
                            ColumnDef::new(Tag::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // Snippets table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(Snippet::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Snippet::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Snippet::ConnectionId).integer().not_null())
                        .col(ColumnDef::new(Snippet::Title).string().not_null())
                        .col(ColumnDef::new(Snippet::Description).string())
                        .col(ColumnDef::new(Snippet::CurrentHistoryId).integer())
                        .col(
                            ColumnDef::new(Snippet::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(Snippet::UpdatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(
                            Index::create()
                                .name("idx_snippet_connection_id")
                                .col(Snippet::ConnectionId),
                        )
                        .index(
                            Index::create()
                                .name("idx_snippet_current_history_id")
                                .col(Snippet::CurrentHistoryId),
                        )
                        .index(
                            Index::create()
                                .name("idx_snippet_updated_at")
                                .col(Snippet::UpdatedAt),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_snippet_collection_id")
                                .from(Snippet::Table, Snippet::ConnectionId)
                                .to(Collection::Table, Collection::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // Nodes table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(Node::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Node::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Node::Kind).string().not_null())
                        .col(ColumnDef::new(Node::SnippetId).integer().not_null())
                        .col(ColumnDef::new(Node::TextId).integer())
                        .col(ColumnDef::new(Node::FileId).integer())
                        .col(ColumnDef::new(Node::MetaJson).string())
                        .col(
                            ColumnDef::new(Node::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(Index::create().name("idx_node_kind").col(Node::Kind))
                        .index(Index::create().name("idx_node_text_id").col(Node::TextId))
                        .index(Index::create().name("idx_node_file_id").col(Node::FileId))
                        .index(
                            Index::create()
                                .name("idx_node_snippet_id")
                                .col(Node::SnippetId),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_node_text_id")
                                .from(Node::Table, Node::TextId)
                                .to(Text::Table, Text::Id)
                                .on_delete(ForeignKeyAction::Restrict)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_node_file_id")
                                .from(Node::Table, Node::FileId)
                                .to(File::Table, File::Id)
                                .on_delete(ForeignKeyAction::Restrict)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_node_snippet_id")
                                .from(Node::Table, Node::SnippetId)
                                .to(Snippet::Table, Snippet::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // Histories table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(History::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(History::Id)
                                .integer()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(History::SnippetId).integer().not_null())
                        .col(ColumnDef::new(History::VersionNumber).integer().not_null())
                        .col(ColumnDef::new(History::Message).string())
                        .col(
                            ColumnDef::new(History::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(History::UpdatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .index(
                            Index::create()
                                .name("idx_history_snippet_id")
                                .col(History::SnippetId),
                        )
                        .index(
                            Index::create()
                                .name("idx_history_created_at")
                                .col(History::CreatedAt),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_history_snippet_id")
                                .from(History::Table, History::SnippetId)
                                .to(Snippet::Table, Snippet::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // History Nodes join table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(HistoryNode::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(HistoryNode::HistoryId).integer().not_null())
                        .col(ColumnDef::new(HistoryNode::NodeId).integer().not_null())
                        .col(ColumnDef::new(HistoryNode::OrderIndex).integer().not_null())
                        .col(ColumnDef::new(HistoryNode::AliasName).string())
                        .col(
                            ColumnDef::new(HistoryNode::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .primary_key(
                            Index::create()
                                .name("pk_history_node")
                                .col(HistoryNode::HistoryId)
                                .col(HistoryNode::NodeId),
                        )
                        .index(
                            Index::create()
                                .name("idx_history_node_node_id")
                                .col(HistoryNode::NodeId),
                        )
                        .index(
                            Index::create()
                                .name("idx_history_node_history_id")
                                .col(HistoryNode::HistoryId),
                        )
                        .index(
                            Index::create()
                                .name("idx_history_node_order")
                                .col(HistoryNode::HistoryId)
                                .col(HistoryNode::OrderIndex)
                                .unique(),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_history_node_history_id")
                                .from(HistoryNode::Table, HistoryNode::HistoryId)
                                .to(History::Table, History::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_history_node_node_id")
                                .from(HistoryNode::Table, HistoryNode::NodeId)
                                .to(Node::Table, Node::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?,
        );

        // Snippet Tags join table
        tables.push(
            manager
                .create_table(
                    Table::create()
                        .table(SnippetTag::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(SnippetTag::SnippetId).integer().not_null())
                        .col(ColumnDef::new(SnippetTag::TagId).integer().not_null())
                        .col(
                            ColumnDef::new(SnippetTag::CreatedAt)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .primary_key(
                            Index::create()
                                .name("pk_snippet_tag")
                                .col(SnippetTag::SnippetId)
                                .col(SnippetTag::TagId),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_snippet_tag_snippet_id")
                                .from(SnippetTag::Table, SnippetTag::SnippetId)
                                .to(Snippet::Table, Snippet::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_snippet_tag_tag_id")
                                .from(SnippetTag::Table, SnippetTag::TagId)
                                .to(Tag::Table, Tag::Id)
                                .on_delete(ForeignKeyAction::Cascade)
                                .on_update(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?,
        );

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse order of creation
        manager
            .drop_table(Table::drop().table(SnippetTag::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(HistoryNode::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(History::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Node::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Snippet::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Tag::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(File::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Text::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Collection::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Collection {
    Table,
    Id,
    Title,
    Description,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Text {
    Table,
    Id,
    Content,
    Kind,
    CreatedAt,
}

#[derive(DeriveIden)]
enum File {
    Table,
    Id,
    StoragePath,
    OriginalFilename,
    MimeType,
    ByteSize,
    Sha256,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Tag {
    Table,
    Id,
    Name,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Node {
    Table,
    Id,
    Kind,
    SnippetId,
    TextId,
    FileId,
    MetaJson,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Snippet {
    Table,
    Id,
    ConnectionId,
    Title,
    Description,
    CurrentHistoryId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum History {
    Table,
    Id,
    SnippetId,
    VersionNumber,
    Message,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum HistoryNode {
    Table,
    HistoryId,
    NodeId,
    OrderIndex,
    AliasName,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SnippetTag {
    Table,
    SnippetId,
    TagId,
    CreatedAt,
}
