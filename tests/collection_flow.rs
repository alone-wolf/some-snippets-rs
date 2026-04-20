#[path = "support/mod.rs"]
mod support;

use some_snippets::modules::content::service::{CreateCollectionInput, UpdateCollectionInput};

#[tokio::test]
async fn create_collection_persists_owner_and_visibility() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = support::setup().await?;

    let collection = ctx
        .content_service
        .create_collection(
            CreateCollectionInput {
                slug: "second-collection".to_owned(),
                name: "Second Collection".to_owned(),
                description: Some("created from test".to_owned()),
                visibility: "public".to_owned(),
            },
            "tester",
        )
        .await?;

    assert_eq!(collection.slug, "second-collection");
    assert_eq!(collection.name, "Second Collection");
    assert_eq!(collection.description.as_deref(), Some("created from test"));
    assert_eq!(collection.visibility, "public");
    assert_eq!(collection.owner_id, "tester");

    Ok(())
}

#[tokio::test]
async fn create_collection_rejects_duplicate_slug() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;

    let result = ctx
        .content_service
        .create_collection(
            CreateCollectionInput {
                slug: "test-collection".to_owned(),
                name: "Duplicate".to_owned(),
                description: None,
                visibility: "private".to_owned(),
            },
            "tester",
        )
        .await;

    let err = result.expect_err("duplicate slug should fail");
    assert!(err.to_string().contains("collection slug already exists"));

    Ok(())
}

#[tokio::test]
async fn update_collection_persists_changes_and_can_clear_description()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;

    let collection = ctx
        .content_service
        .update_collection(
            ctx.collection_id,
            UpdateCollectionInput {
                slug: Some("updated-collection".to_owned()),
                name: Some("Updated Collection".to_owned()),
                description: Some(None),
                visibility: Some("public".to_owned()),
            },
        )
        .await?;

    assert_eq!(collection.slug, "updated-collection");
    assert_eq!(collection.name, "Updated Collection");
    assert_eq!(collection.description, None);
    assert_eq!(collection.visibility, "public");

    Ok(())
}

#[tokio::test]
async fn update_collection_rejects_duplicate_slug() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;

    ctx.content_service
        .create_collection(
            CreateCollectionInput {
                slug: "occupied-slug".to_owned(),
                name: "Occupied".to_owned(),
                description: None,
                visibility: "private".to_owned(),
            },
            "tester",
        )
        .await?;

    let result = ctx
        .content_service
        .update_collection(
            ctx.collection_id,
            UpdateCollectionInput {
                slug: Some("occupied-slug".to_owned()),
                name: None,
                description: None,
                visibility: None,
            },
        )
        .await;

    let err = result.expect_err("duplicate slug should fail");
    assert!(err.to_string().contains("collection slug already exists"));

    Ok(())
}
