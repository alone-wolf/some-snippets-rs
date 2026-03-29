#[path = "support/mod.rs"]
mod support;

use some_snippets::{
    modules::node::model::{FileNodeInput, TextNodeInput},
    storage::snapshot::path::format_version,
};

#[tokio::test]
async fn draft_only_text_updates_in_place() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;
    let content = ctx.create_content("draft-only", "Draft Only").await?;
    let node = ctx
        .node_service
        .create_text_node(
            content.id,
            TextNodeInput {
                text: "hello".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;

    let result = ctx
        .node_service
        .update_text_node(
            node.id,
            TextNodeInput {
                text: "hello world".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;

    assert!(!result.copy_on_write);
    assert_eq!(result.old_node.id, result.new_node.id);
    assert_eq!(result.new_node.version, 0);

    let draft = ctx.content_service.get_draft_snapshot(content.id).await?;
    assert_eq!(draft.nodes.len(), 1);
    assert_eq!(draft.nodes[0].node_id, node.id);

    Ok(())
}

#[tokio::test]
async fn committed_text_updates_copy_on_write() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;
    let content = ctx.create_content("text-cow", "Text COW").await?;
    let node = ctx
        .node_service
        .create_text_node(
            content.id,
            TextNodeInput {
                text: "v1".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;
    ctx.content_service
        .commit_latest(content.id, "tester")
        .await?;

    let result = ctx
        .node_service
        .update_text_node(
            node.id,
            TextNodeInput {
                text: "v2".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;

    assert!(result.copy_on_write);
    assert_ne!(result.old_node.id, result.new_node.id);
    assert_eq!(result.old_node.uuid, result.new_node.uuid);
    assert_eq!(result.new_node.version, result.old_node.version + 1);

    let draft = ctx.content_service.get_draft_snapshot(content.id).await?;
    assert_eq!(draft.nodes[0].node_id, result.new_node.id);

    Ok(())
}

#[tokio::test]
async fn committed_file_updates_copy_on_write() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;
    let content = ctx.create_content("file-cow", "File COW").await?;
    let node = ctx
        .node_service
        .create_file_node(
            content.id,
            FileNodeInput {
                filename: "demo.png".to_owned(),
                bucket: "content-assets".to_owned(),
                object_key: "files/demo-v1.png".to_owned(),
                mime_type: Some("image/png".to_owned()),
                size_bytes: 12,
                checksum: Some("sha256:old".to_owned()),
                meta: None,
            },
            "tester",
        )
        .await?;
    ctx.content_service
        .commit_latest(content.id, "tester")
        .await?;

    let result = ctx
        .node_service
        .update_file_node(
            node.node.id,
            FileNodeInput {
                filename: "demo-v2.png".to_owned(),
                bucket: "content-assets".to_owned(),
                object_key: "files/demo-v2.png".to_owned(),
                mime_type: Some("image/png".to_owned()),
                size_bytes: 24,
                checksum: Some("sha256:new".to_owned()),
                meta: None,
            },
            "tester",
        )
        .await?;

    assert!(result.copy_on_write);
    assert_ne!(result.old_node.id, result.new_node.id);
    assert_eq!(result.old_node.uuid, result.new_node.uuid);
    assert_eq!(result.new_node.version, result.old_node.version + 1);

    let current = ctx
        .node_service
        .get_node_with_file(result.new_node.id)
        .await?;
    let file = current.file_metadata.expect("file metadata");
    assert_eq!(file.filename, "demo-v2.png");
    assert_eq!(file.object_key, "files/demo-v2.png");

    Ok(())
}

#[tokio::test]
async fn draft_latest_version_shapes_and_naming() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;
    let content = ctx.create_content("versioning", "Versioning").await?;
    ctx.node_service
        .create_text_node(
            content.id,
            TextNodeInput {
                text: "snapshot".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;

    let latest = ctx
        .content_service
        .commit_latest(content.id, "tester")
        .await?;
    let version = ctx
        .content_service
        .create_version(content.id, Some("release-candidate".to_owned()), "tester")
        .await?;
    let versions = ctx.content_service.list_versions(content.id).await?;
    let draft = ctx.content_service.get_draft_snapshot(content.id).await?;

    let draft_json = serde_json::to_value(&draft)?;
    let latest_json = serde_json::to_value(&latest)?;
    let version_json = serde_json::to_value(&version)?;

    assert!(draft_json["nodes"][0].get("nodeId").is_some());
    assert!(draft_json["nodes"][0].get("uuid").is_none());
    assert!(latest_json["nodes"][0].get("uuid").is_some());
    assert!(version_json["nodes"][0].get("uuid").is_some());
    assert_eq!(version_json["version"].as_i64(), Some(1));
    assert_eq!(format_version(1), "000001");
    assert!(versions[0].snapshot_key.ends_with("content.000001.json"));

    Ok(())
}

#[tokio::test]
async fn rollback_restores_ref_only_draft_without_overwriting_latest()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = support::setup().await?;
    let content = ctx.create_content("rollback", "Rollback").await?;
    let original = ctx
        .node_service
        .create_text_node(
            content.id,
            TextNodeInput {
                text: "v1".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;
    ctx.content_service
        .commit_latest(content.id, "tester")
        .await?;
    let version = ctx
        .content_service
        .create_version(content.id, Some("v1".to_owned()), "tester")
        .await?;

    let edited = ctx
        .node_service
        .update_text_node(
            original.id,
            TextNodeInput {
                text: "v2".to_owned(),
                meta: None,
            },
            "tester",
        )
        .await?;
    assert!(edited.copy_on_write);

    let rolled_back = ctx
        .content_service
        .rollback_to_version(content.id, version.version, "tester")
        .await?;
    let latest = ctx.content_service.get_latest_snapshot(content.id).await?;
    let draft_json = serde_json::to_value(&rolled_back)?;

    assert_eq!(latest.nodes[0].node_id, original.id);
    assert_eq!(rolled_back.nodes.len(), 1);
    assert!(draft_json["nodes"][0].get("nodeId").is_some());
    assert_eq!(draft_json["nodes"][0].as_object().map(|m| m.len()), Some(1));

    Ok(())
}
