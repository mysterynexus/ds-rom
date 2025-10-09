use std::{
    backtrace::Backtrace,
    io::{BufWriter, Cursor},
    path::{Path, PathBuf},
};

use ezfs::FilesystemError;
use image::{
    codecs::png::PngEncoder, DynamicImage, EncodableLayout, ExtendedColorType, GrayImage, ImageEncoder, ImageError,
    ImageFormat, RgbaImage,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_yml::Error as SerdeYmlError;
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum FileError {
    #[snafu(display("the file '{path:?}' was not found:\n{backtrace}"))]
    FileNotFound { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("parent directory does not exist for file '{path:?}':\n{backtrace}"))]
    FileParentNotFound { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("the directory '{path:?}' was not found:\n{backtrace}"))]
    DirNotFound { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("failed to read file '{path:?}', ran out of memory:\n{backtrace}"))]
    FileOutOfMemory { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("failed to read directory '{path:?}', ran out of memory:\n{backtrace}"))]
    DirOutOfMemory { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("the file '{path:?}' already exists:\n{backtrace}"))]
    AlreadyExists { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("filesystem error for '{path:?}': {source}"))]
    Fs { path: PathBuf, source: FilesystemError, backtrace: Backtrace },
    // #[snafu(transparent)]
    // Path { source: fusio::path::Error, backtrace: Backtrace },
    #[snafu(display("unsupported image format for '{path:?}':\n{backtrace}"))]
    UnsupportedImageFormat { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("failed to decode image '{path:?}': {source}"))]
    ImageDecode { path: PathBuf, source: ImageError, backtrace: Backtrace },
}

/// Wrapper for [`AsyncFs::open_options`] with clearer errors.
pub async fn open_file<P: AsRef<Path>>(path: P) -> Result<ezfs::File, FileError> {
    ezfs::open(path.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

/// Wrapper for [`AsyncFs::open_options`] with clearer errors when creating files.
pub async fn create_file<P: AsRef<Path>>(path: P) -> Result<ezfs::File, FileError> {
    ezfs::create(path.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

/// Creates a file using [`create_file`] and its parent directories using [`create_dir_all`].
pub async fn create_file_and_dirs<P: AsRef<Path>>(path: P) -> Result<ezfs::File, FileError> {
    let path_ref = path.as_ref();

    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).await?;
    }

    create_file(path_ref).await
}

/// Wrapper for [`async_fs::read`] with clearer errors.
pub async fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, FileError> {
    ezfs::read(path.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

/// Wrapper for [`Fs::open_options`] with clearer errors when writing files.
pub async fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), FileError> {
    ezfs::write(path.as_ref(), contents.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

/// Wrapper for [`Fs::open_options`] with clearer errors.
pub async fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String, FileError> {
    let data = read_file(path).await?;
    Ok(String::from_utf8(data).unwrap())
}

/// Wrapper for [`Fs::list`] with clearer errors.
pub async fn read_dir<P: AsRef<Path>>(path: P) -> Result<ezfs::Dir, FileError> {
    ezfs::read_dir(path.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

/// Wrapper for [`AsyncFs::create_dir_all`] with clearer errors.
pub async fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<(), FileError> {
    ezfs::create_dir_all(path.as_ref()).await.context(FsSnafu { path: path.as_ref() })
}

pub async fn read_yaml<T>(mut file: ezfs::File) -> Result<T, SerdeYmlError>
where
    T: DeserializeOwned,
{
    serde_yml::from_slice(&file.read().await.unwrap())
}

pub async fn write_yaml<T>(file: &mut ezfs::File, value: &T) -> Result<(), SerdeYmlError>
where
    T: Serialize,
{
    let mut serialized = Vec::new();
    serde_yml::to_writer(&mut serialized, value)?;
    file.write(&serialized).await.unwrap();
    Ok(())
}

pub async fn read_image(path: &Path) -> Result<DynamicImage, FileError> {
    let data = read_file(path).await?;
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap();
    let format = ImageFormat::from_extension(ext).unwrap();
    let image = image::load(Cursor::new(data), format).context(ImageDecodeSnafu { path: path.to_path_buf() })?;
    Ok(image)
}

pub async fn write_rgba_image(image: &RgbaImage, path: &Path) -> Result<(), FileError> {
    write_raw_image(image.as_bytes(), image.width(), image.height(), path, ExtendedColorType::Rgba8).await
}

pub async fn write_gray_image(image: &GrayImage, path: &Path) -> Result<(), FileError> {
    write_raw_image(image.as_bytes(), image.width(), image.height(), path, ExtendedColorType::L8).await
}

async fn write_raw_image(
    data: &[u8],
    width: u32,
    height: u32,
    path: &Path,
    color_type: ExtendedColorType,
) -> Result<(), FileError> {
    let mut buffer = BufWriter::new(Vec::new());
    PngEncoder::new(&mut buffer).write_image(data, width, height, color_type).unwrap();
    write_file(path, &buffer.into_inner().unwrap()).await?;
    Ok(())
}
