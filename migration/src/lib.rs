pub use sea_orm_migration::prelude::*;

mod m20260329_000001_create_collections;
mod m20260329_000002_create_contents;
mod m20260329_000003_create_content_versions;
mod m20260329_000004_create_nodes;
mod m20260329_000005_create_file_metadata;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260329_000001_create_collections::Migration),
            Box::new(m20260329_000002_create_contents::Migration),
            Box::new(m20260329_000003_create_content_versions::Migration),
            Box::new(m20260329_000004_create_nodes::Migration),
            Box::new(m20260329_000005_create_file_metadata::Migration),
        ]
    }
}
