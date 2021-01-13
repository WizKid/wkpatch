use std::str;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time;
use walkdir::WalkDir;
use integer_encoding::{VarIntWriter, VarIntReader};
use num_enum;

#[repr(u8)]
#[derive(Debug, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
enum InstrType {
    Add = 1,
    Remove = 2,
    Rename = 3,
    BinaryPatch = 4,
}

enum Instr<'a> {
    Add { name: &'a str, content: Box<dyn Read + 'a> },
    Remove { name: &'a str },
    Rename { name: &'a str, new_name: &'a str },
    BinaryPatch { name: &'a str, content: Box<dyn Read + 'a> },
    // Patcher { name: &'a str },
}

struct InstrInterator<'a> {
    curr: u32,
    content: &'a [u8],
}

impl<'a> Iterator for InstrInterator<'a> {
    type Item = Instr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.curr += 1;
        match self.curr {
            1 => Some(Instr::Remove { name: str::from_utf8(&self.content[0..7]).unwrap() }),
            2 => Some(Instr::Rename { name: str::from_utf8(&self.content[0..7]).unwrap(), new_name: str::from_utf8(&self.content[0..7]).unwrap() }),
            3 => Some(Instr::Add { name: str::from_utf8(&self.content[0..7]).unwrap(), content: Box::new(Cursor::new(&self.content[7..8])) }),
            4 => Some(Instr::BinaryPatch { name: str::from_utf8(&self.content[0..7]).unwrap(), content: Box::new(Cursor::new(&self.content[7..8])) }),
            _ => None
        }
    }
}

fn test_fn() {
    let content = "foo.logb".as_bytes();

    let iter = InstrInterator { curr: 0, content };

    for instr in iter {
        match instr {
            Instr::Add { name, mut content } => {
                let mut bytes = vec![];
                content.read_to_end(&mut bytes).unwrap();
                println!("Add {} {:02X?}", name, bytes);
            },
            Instr::Remove { name } => println!("Remove {}", name),
            Instr::Rename { name, new_name } => println!("Rename {} {}", name, new_name),
            Instr::BinaryPatch { name, mut content } => {
                let mut bytes = vec![];
                content.read_to_end(&mut bytes).unwrap();
                println!("BinaryPatch {} {:02X?}", name, bytes);
            }
        }
    }
}

struct InputDir {
    base: PathBuf,
    files: HashSet<PathBuf>,
}

impl InputDir {
    fn new(base: &Path) -> Self {
        let files: HashSet<PathBuf> = WalkDir::new(base)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir())
            .map(|e| e.path().strip_prefix(base).unwrap().to_owned())
            .collect();
        Self {
            base: base.to_path_buf(),
            files,
        }
    }
}

struct PatchReader<'a> {
    input: &'a mut dyn Read,
}

impl<'a> PatchReader<'a> {
    fn new(input: &'a mut dyn Read) -> Self {
        Self { input }
    }

    fn read_instr_type(&mut self) -> InstrType {
        let mut t = self.read_varint::<u8>().unwrap();
        InstrType::try_from(t).unwrap()
    }

    fn read_bytes(&mut self) -> Vec<u8> {
        let len: usize = self.read_varint().unwrap();
        let mut buffer = vec![0; len];
        self.read_exact(&mut buffer).unwrap();
        buffer
    }

    fn read_path(&mut self) -> PathBuf {
        PathBuf::from(str::from_utf8(&self.read_bytes()).unwrap())
    }
}

impl<'a> std::io::Read for PatchReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

struct PatchWriter<'a> {
    output: &'a mut dyn io::Write,
}

impl<'a> PatchWriter<'a> {
    fn new(output: &'a mut dyn Write) -> Self {
        Self { output }
    }

    fn write_instr_type(&mut self, t: InstrType) {
        self.write_varint(t as u8);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_varint(bytes.len());
        self.write_all(bytes);
    }
}

impl<'a> io::Write for PatchWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

struct PatchMaker {
    old_input: InputDir,
    new_input: InputDir,
}

impl PatchMaker {
    fn new(old_input: InputDir, new_input: InputDir) -> Self {
        Self { old_input, new_input }
    }

    fn create(&mut self, output: &mut PatchWriter) -> u32 {
        let mut i = 0u32;
        println!("Start remove");
        for p in self.old_input.files.difference(&self.new_input.files) {
            self.remove(output, p);
            i += 1;
            println!("Remove {} {}", i, p.display());
        }
        println!("Start add");
        for p in self.new_input.files.difference(&self.old_input.files) {
            self.add(output, p);
            i += 1;
            println!("Add {} {}", i, p.display());
        }
        println!("Start diff");
        for p in self.old_input.files.intersection(&self.new_input.files) {
            println!("Diff Start {} {}", i, p.display());
            self.diff(output, p);
            i += 1;
            println!("Diff End {} {}", i, p.display());
        }
        i
    }

    fn add(&self, output: &mut PatchWriter, p: &Path) {
        output.write_instr_type(InstrType::Add);
        output.write_bytes(p.as_os_str().to_str().unwrap().as_bytes());
        let mut full_path = self.new_input.base.to_path_buf();
        full_path.push(p);
        let buffer = std::fs::read(&full_path).unwrap();
        output.write_bytes(&buffer);
    }

    fn remove(&self, output: &mut PatchWriter, p: &Path) {
        output.write_instr_type(InstrType::Remove);
        output.write_bytes(p.as_os_str().to_str().unwrap().as_bytes());
    }

    fn diff(&self, output: &mut PatchWriter, p: &Path) {
        let mut old_full_path = self.old_input.base.to_path_buf();
        old_full_path.push(p);
        let old_buffer = std::fs::read(&old_full_path).unwrap();

        let mut new_full_path = self.new_input.base.to_path_buf();
        new_full_path.push(p);
        let new_buffer = std::fs::read(&new_full_path).unwrap();

        let mut output_buffer = Vec::new();
        bidiff::simple_diff_with_params(&old_buffer, &new_buffer, &mut output_buffer, &bidiff::DiffParams::new(4, Some(20971520)).unwrap());

        output.write_instr_type(InstrType::BinaryPatch);
        output.write_bytes(p.as_os_str().to_str().unwrap().as_bytes());
        output.write_bytes(&output_buffer);
    }
}

struct PatchApplier {
    base: PathBuf,
}

impl PatchApplier {
    fn new(base: &Path) -> Self {
        Self {
            base: base.to_path_buf(),
        }
    }

    fn apply(&self, instr_count: u32, patch: &mut PatchReader) {
        let start = time::Instant::now();
        for _i in 0..instr_count {
            let t = patch.read_instr_type();
            println!("InstrType: {:?}", t);
            match t {
                InstrType::Add => {
                    let path = patch.read_path();
                    println!("Add {:?}", path);

                    let len: u64 = patch.read_varint().unwrap();

                    let mut full_path = self.base.clone();
                    full_path.push(path);

                    let mut file_writer = File::create(full_path).unwrap();
                    io::copy(&mut patch.take(len), &mut file_writer);
                },
                InstrType::BinaryPatch => {
                    let path = patch.read_path();
                    println!("Binary Patch {:?}", path);

                    let len: u64 = patch.read_varint().unwrap();

                    let mut full_path = self.base.clone();
                    full_path.push(path);

                    let file_reader = File::open(&full_path).unwrap();

                    let mut temp_path = self.base.clone();
                    temp_path.push("ptch.tmp");

                    let mut file_writer = File::create(&temp_path).unwrap();

                    let mut patch_reader = patch.take(len);

                    let mut patched_reader = bipatch::Reader::new(patch_reader, file_reader).unwrap();

                    io::copy(&mut patched_reader, &mut file_writer);

                    fs::rename(&temp_path, &full_path);
                    println!("Diff applied {:?} {:?}", temp_path.display(), full_path.display())
                },
                InstrType::Remove => {
                    let path = patch.read_path();
                    println!("Remove {:?}", path);
                    let mut full_path = self.base.clone();
                    full_path.push(path);
                    fs::remove_file(full_path);
                },
                InstrType::Rename => {
                    let from_path = patch.read_path();
                    let to_path = patch.read_path();
                    println!("{:?} {:?}", from_path, to_path);
                }
            }
        }

        let elapsed = start.elapsed();

        // Debug format
        println!("Patching took: {:?}", elapsed); 
    }
}

pub fn create_patch(from_directory: &Path, to_directory: &Path, patch_path: &Path) {
    let old_input = InputDir::new(from_directory);
    let new_input = InputDir::new(to_directory);
    let mut file_writer = File::create(patch_path).unwrap();
    file_writer.write(b"PTCH\0\0\0\0");
    let mut zstd_writer = zstd::stream::Encoder::new(&mut file_writer, 10).unwrap();
    let mut patch_writer = PatchWriter::new(&mut zstd_writer);
    let mut patch_maker = PatchMaker::new(old_input, new_input);
    let instr_count = patch_maker.create(&mut patch_writer);
    zstd_writer.finish();
    file_writer.seek(io::SeekFrom::Start(4));
    file_writer.write(&instr_count.to_be_bytes());
}

pub fn apply_patch(patch_path: &Path, directory: &Path) {
    let mut file_reader = File::open(patch_path).unwrap();

    let mut buf = [0; 4];
    file_reader.read_exact(&mut buf);
    println!("HEADER {:?}", buf);

    file_reader.read_exact(&mut buf);
    let instr_count = u32::from_be_bytes(buf);
    println!("Instr count {}", instr_count);

    let mut zstd_reader = zstd::stream::Decoder::new(&mut file_reader).unwrap();
    let mut patch_reader = PatchReader::new(&mut zstd_reader);

    let a = PatchApplier::new(directory);
    a.apply(instr_count, &mut patch_reader);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // makepatch();
        // applypatch();
        assert_eq!(2 + 2, 4);
    }
}
