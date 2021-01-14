extern crate clap;
use clap::{App, Arg, SubCommand, AppSettings, crate_version};
use std::path::Path;
use wkpatch;

fn main() {
    let matches = App::new("wkpatch")
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("create")
            .about("Create a patch between two directories")
            .arg(Arg::with_name("FROM_DIRECTORY")
                .help("Sets directory to patch from")
                .required(true)
                .index(1))
            .arg(Arg::with_name("TO_DIRECTORY")
                .help("Sets directory to patch to")
                .required(true)
                .index(2))
            .arg(Arg::with_name("PATCH_PATH")
                .help("Sets the patch path to create")
                .required(true)
                .index(3))
        )
        .subcommand(SubCommand::with_name("apply")
            .about("Apply a patch to a directory")
            .arg(Arg::with_name("PATCH_PATH")
                .help("Sets the patch path")
                .required(true)
                .index(1))
            .arg(Arg::with_name("DIRECTORY")
                .help("Sets directory to patch")
                .required(true)
                .index(2)))
        .get_matches();

    match matches.subcommand() {
        ("create",   Some(sub_match)) => {
            let from_directory = Path::new(sub_match.value_of("FROM_DIRECTORY").unwrap());
            let to_directory = Path::new(sub_match.value_of("TO_DIRECTORY").unwrap());
            let patch_path = Path::new(sub_match.value_of("PATCH_PATH").unwrap());
            println!("create was used {} {} {}", from_directory.display(), to_directory.display(), patch_path.display());
            let res = wkpatch::create_patch(from_directory, to_directory, patch_path);
            if let Err(err) = res {
                println!("{:?}", err);
            }
        },
        ("apply",  Some(sub_match)) => {
            let patch_path = Path::new(sub_match.value_of("PATCH_PATH").unwrap());
            let directory = Path::new(sub_match.value_of("DIRECTORY").unwrap());
            println!("apply was used {} {}", patch_path.display(), directory.display());
            let res = wkpatch::apply_patch(patch_path, directory);
            if let Err(err) = res {
                println!("{:?}", err);
            }
        },
        _ => {
            println!("unknown");
        },
    }
}
