use std::str;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::fs;
use std::fs::File;
use std::hash::Hasher;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use walkdir::WalkDir;
use integer_encoding::{VarIntWriter, VarIntReader};
use num_enum;
use seahash;

#[repr(u8)]
#[derive(Debug, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
enum InstrType {
    Same = 1,
    Add = 2,
    Remove = 3,
    BinaryPatch = 4,
}

#[derive(Debug)]
pub enum CreateError {
    IO(io::Error)
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CreateError::IO(_) => write!(f, "I/O error"),
        }
    }
}

impl error::Error for CreateError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            CreateError::IO(e) => Some(e),
        }
    }
}

impl From<io::Error> for CreateError {
    fn from(source: io::Error) -> Self {
        CreateError::IO(source)
    }
}

#[derive(Debug)]
pub enum ApplyError {
    ChecksumMismatch,
    IO(io::Error)
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ApplyError::ChecksumMismatch => write!(f, "Checksum mismatch!"),
            ApplyError::IO(_) => write!(f, "I/O error"),
        }
    }
}

impl error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ApplyError::ChecksumMismatch => None,
            ApplyError::IO(e) => Some(e),
        }
    }
}

impl From<io::Error> for ApplyError {
    fn from(source: io::Error) -> Self {
        ApplyError::IO(source)
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

    fn read_instr_type(&mut self) -> Result<InstrType, ApplyError> {
        let t = self.read_varint::<u8>()?;
        Ok(InstrType::try_from(t).unwrap())
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, io::Error> {
        let len: usize = self.read_varint()?;
        let mut buffer = vec![0; len];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_path(&mut self) -> Result<PathBuf, io::Error> {
        let buffer = self.read_bytes()?;
        Ok(PathBuf::from(str::from_utf8(&buffer).unwrap()))
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

    fn write_instr_type(&mut self, t: InstrType) -> Result<(), io::Error> {
        self.write_varint(t as u8)?;
        Ok(())
    }

    fn write_path(&mut self, p: &Path) -> Result<(), io::Error> {
        self.write_bytes(p.as_os_str().to_str().unwrap().as_bytes())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), io::Error> {
        self.write_varint(bytes.len())?;
        self.write_all(bytes)
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

fn calc_hash(buffer: &[u8]) -> u64 {
    let hash = seahash::hash(&buffer);
    println!("{:?}", hash);
    hash
}

impl PatchMaker {
    fn new(old_input: InputDir, new_input: InputDir) -> Self {
        Self { old_input, new_input }
    }

    fn create(&mut self, output: &mut PatchWriter) -> Result<u32, CreateError> {
        let mut i = 0u32;
        println!("Start remove");
        for p in self.old_input.files.difference(&self.new_input.files) {
            self.remove(output, p)?;
            i += 1;
            println!("Remove {} {}", i, p.display());
        }
        println!("Start add");
        for p in self.new_input.files.difference(&self.old_input.files) {
            self.add(output, p)?;
            i += 1;
            println!("Add {} {}", i, p.display());
        }
        println!("Start diff");
        for p in self.old_input.files.intersection(&self.new_input.files) {
            println!("Diff Start {} {}", i, p.display());
            self.diff(output, p)?;
            i += 1;
            println!("Diff End {} {}", i, p.display());
        }
        Ok(i)
    }

    fn read_file(&self, base: &Path, p: &Path) -> Result<Vec<u8>, io::Error> {
        let mut full_path = base.to_path_buf();
        full_path.push(p);
        std::fs::read(&full_path)
    }

    fn add(&self, output: &mut PatchWriter, p: &Path) -> Result<(), CreateError> {
        output.write_instr_type(InstrType::Add)?;
        output.write_path(p)?;
        let buffer = self.read_file(&self.new_input.base, p)?;
        output.write_u64::<LittleEndian>(calc_hash(&buffer))?;
        output.write_bytes(&buffer)?;
        Ok(())
    }

    fn remove(&self, output: &mut PatchWriter, p: &Path) -> Result<(), CreateError> {
        output.write_instr_type(InstrType::Remove)?;
        output.write_path(p)?;
        let buffer = self.read_file(&self.old_input.base, p)?;
        output.write_u64::<LittleEndian>(calc_hash(&buffer))?;
        Ok(())
    }

    fn diff(&self, output: &mut PatchWriter, p: &Path) -> Result<(), CreateError> {
        let old_buffer = self.read_file(&self.old_input.base, p)?;
        let new_buffer = self.read_file(&self.new_input.base, p)?;

        let old_hash = calc_hash(&old_buffer);
        let new_hash = calc_hash(&new_buffer);

        if old_hash == new_hash && old_buffer == new_buffer {
            output.write_instr_type(InstrType::Same)?;
            output.write_path(p)?;
            output.write_u64::<LittleEndian>(new_hash)?;
        } else {
            let mut output_buffer = Vec::new();
            bidiff::simple_diff_with_params(&old_buffer, &new_buffer, &mut output_buffer, &bidiff::DiffParams::new(4, Some(20971520)).unwrap());

            output.write_instr_type(InstrType::BinaryPatch)?;
            output.write_path(p)?;
            output.write_u64::<LittleEndian>(old_hash)?;
            output.write_u64::<LittleEndian>(new_hash)?;
            output.write_bytes(&output_buffer)?;
        }

        Ok(())
    }
}

struct HasherPassthruWriter<'a> {
    hasher: &'a mut dyn Hasher,
    writer: &'a mut dyn Write,
}

impl<'a> HasherPassthruWriter<'a> {
    fn new(hasher: &'a mut dyn Hasher, writer: &'a mut dyn Write) -> Self {
        Self { hasher, writer }
    }
}

impl<'a> io::Write for HasherPassthruWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.write(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
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

    fn apply(&self, instr_count: u32, patch: &mut PatchReader) -> Result<(), ApplyError> {
        let start = time::Instant::now();
        for _i in 0..instr_count {
            let t = patch.read_instr_type()?;
            println!("InstrType: {:?}", t);
            match t {
                InstrType::Same => {
                    let path = patch.read_path()?;
                    let hash = patch.read_u64::<LittleEndian>()?;
                    println!("Same {:?} {:?}", path, hash);
                },
                InstrType::Add => {
                    let path = patch.read_path()?;
                    let hash = patch.read_u64::<LittleEndian>()?;
                    println!("Add {:?} {:?}", path, hash);

                    let len: u64 = patch.read_varint()?;

                    let mut full_path = self.base.clone();
                    full_path.push(path);

                    let mut file_writer = File::create(full_path)?;
                    let mut hasher = seahash::SeaHasher::default();
                    let mut hash_writer = HasherPassthruWriter::new(&mut hasher, &mut file_writer);
                    io::copy(&mut patch.take(len), &mut hash_writer)?;

                    if hasher.finish() != hash {
                        return Err(ApplyError::ChecksumMismatch);
                    }

                    println!("Write {:?}", hasher.finish());
                },
                InstrType::BinaryPatch => {
                    let path = patch.read_path()?;
                    let from_hash = patch.read_u64::<LittleEndian>()?;
                    let to_hash = patch.read_u64::<LittleEndian>()?;
                    println!("Binary Patch {:?} {:?} {:?}", path, from_hash, to_hash);

                    let len: u64 = patch.read_varint()?;

                    let mut full_path = self.base.clone();
                    full_path.push(path);

                    let file_reader = File::open(&full_path)?;

                    let mut temp_path = self.base.clone();
                    temp_path.push("ptch.tmp");

                    let mut file_writer = File::create(&temp_path)?;
                    let mut hasher = seahash::SeaHasher::default();
                    let mut hash_writer = HasherPassthruWriter::new(&mut hasher, &mut file_writer);

                    let patch_reader = patch.take(len);

                    let mut patched_reader = bipatch::Reader::new(patch_reader, file_reader).unwrap();

                    io::copy(&mut patched_reader, &mut hash_writer)?;

                    if hasher.finish() != to_hash {
                        return Err(ApplyError::ChecksumMismatch);
                    }

                    fs::rename(&temp_path, &full_path)?;
                    println!("Diff applied {:?} {:?} {:?} {:?}", temp_path.display(), full_path.display(), to_hash, hasher.finish());
                },
                InstrType::Remove => {
                    let path = patch.read_path()?;
                    let hash = patch.read_u64::<LittleEndian>()?;
                    println!("Remove {:?} {:?}", path, hash);
                    let mut full_path = self.base.clone();
                    full_path.push(path);
                    fs::remove_file(full_path)?;
                }
            }
        }

        let elapsed = start.elapsed();

        // Debug format
        println!("Patching took: {:?}", elapsed); 
        Ok(())
    }
}

pub fn create_patch(from_directory: &Path, to_directory: &Path, patch_path: &Path) -> Result<(), CreateError> {
    let old_input = InputDir::new(from_directory);
    let new_input = InputDir::new(to_directory);
    let mut file_writer = File::create(patch_path)?;
    file_writer.write(b"PTCH\0\0\0\0")?;
    let mut zstd_writer = zstd::stream::Encoder::new(&mut file_writer, 10)?;
    let mut patch_writer = PatchWriter::new(&mut zstd_writer);
    let mut patch_maker = PatchMaker::new(old_input, new_input);
    let instr_count = patch_maker.create(&mut patch_writer)?;
    zstd_writer.finish()?;
    file_writer.seek(io::SeekFrom::Start(4))?;
    file_writer.write(&instr_count.to_be_bytes())?;

    Ok(())
}

pub fn apply_patch(patch_path: &Path, directory: &Path) -> Result<(), ApplyError> {
    let mut file_reader = File::open(patch_path)?;

    let mut buf = [0; 4];
    file_reader.read_exact(&mut buf)?;
    println!("HEADER {:?}", buf);

    file_reader.read_exact(&mut buf)?;
    let instr_count = u32::from_be_bytes(buf);
    println!("Instr count {}", instr_count);

    let mut zstd_reader = zstd::stream::Decoder::new(&mut file_reader)?;
    let mut patch_reader = PatchReader::new(&mut zstd_reader);

    let a = PatchApplier::new(directory);
    a.apply(instr_count, &mut patch_reader)?;
    Ok(())
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
