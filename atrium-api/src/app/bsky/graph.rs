// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.graph` namespace.
pub mod block;
pub mod defs;
pub mod follow;
pub mod get_actor_starter_packs;
pub mod get_blocks;
pub mod get_followers;
pub mod get_follows;
pub mod get_known_followers;
pub mod get_list;
pub mod get_list_blocks;
pub mod get_list_mutes;
pub mod get_lists;
pub mod get_mutes;
pub mod get_relationships;
pub mod get_starter_pack;
pub mod get_starter_packs;
pub mod get_suggested_follows_by_actor;
pub mod list;
pub mod listblock;
pub mod listitem;
pub mod mute_actor;
pub mod mute_actor_list;
pub mod mute_thread;
pub mod search_starter_packs;
pub mod starterpack;
pub mod unmute_actor;
pub mod unmute_actor_list;
pub mod unmute_thread;
#[derive(Debug)]
pub struct Block;
impl crate::types::Collection for Block {
    const NSID: &'static str = "app.bsky.graph.block";
    type Record = block::Record;
}
#[derive(Debug)]
pub struct Follow;
impl crate::types::Collection for Follow {
    const NSID: &'static str = "app.bsky.graph.follow";
    type Record = follow::Record;
}
#[derive(Debug)]
pub struct List;
impl crate::types::Collection for List {
    const NSID: &'static str = "app.bsky.graph.list";
    type Record = list::Record;
}
#[derive(Debug)]
pub struct Listblock;
impl crate::types::Collection for Listblock {
    const NSID: &'static str = "app.bsky.graph.listblock";
    type Record = listblock::Record;
}
#[derive(Debug)]
pub struct Listitem;
impl crate::types::Collection for Listitem {
    const NSID: &'static str = "app.bsky.graph.listitem";
    type Record = listitem::Record;
}
#[derive(Debug)]
pub struct Starterpack;
impl crate::types::Collection for Starterpack {
    const NSID: &'static str = "app.bsky.graph.starterpack";
    type Record = starterpack::Record;
}
