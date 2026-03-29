pub fn draft_snapshot_key(content_id: i64) -> String {
    format!("contents/{content_id}/content.draft.json")
}

pub fn latest_snapshot_key(content_id: i64) -> String {
    format!("contents/{content_id}/content.latest.json")
}

pub fn version_snapshot_key(content_id: i64, version: i32) -> String {
    format!(
        "contents/{content_id}/content.{}.json",
        format_version(version)
    )
}

pub fn format_version(version: i32) -> String {
    format!("{version:06}")
}
