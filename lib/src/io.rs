use std::{
    backtrace::Backtrace,
    io::{BufWriter, Cursor},
    path::{Path, PathBuf},
};

use fusio::{error::Error as FusioError, fs::OpenOptions, path::Path as FusioPath, Fs, Read, Write};
use futures::StreamExt;
use image::{
    codecs::png::PngEncoder, DynamicImage, EncodableLayout, ExtendedColorType, GrayImage, ImageEncoder, ImageError,
    ImageFormat, RgbaImage,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_yml::Error as SerdeYmlError;
use snafu::{ResultExt, Snafu};

#[cfg(not(target_arch = "wasm32"))]
type FsImpl = fusio::disk::AsyncFs;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) static FS: fusio::disk::AsyncFs = fusio::disk::AsyncFs;
#[cfg(target_arch = "wasm32")]
type FsImpl = fusio::disk::OPFS;
#[cfg(target_arch = "wasm32")]
pub(crate) static FS: fusio::disk::OPFS = fusio::disk::OPFS;

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
    Fs { path: PathBuf, source: FusioError, backtrace: Backtrace },
    #[snafu(transparent)]
    Path { source: fusio::path::Error, backtrace: Backtrace },
    #[snafu(display("unsupported image format for '{path:?}':\n{backtrace}"))]
    UnsupportedImageFormat { path: PathBuf, backtrace: Backtrace },
    #[snafu(display("failed to decode image '{path:?}': {source}"))]
    ImageDecode { path: PathBuf, source: ImageError, backtrace: Backtrace },
}

/// Wrapper for [`AsyncFs::open_options`] with clearer errors.
pub async fn open_file<P: AsRef<Path>>(path: P) -> Result<<FsImpl as Fs>::File, FileError> {
    let fusio_path = FusioPath::new(path.as_ref())?;
    let options = OpenOptions::default();

    match FS.open_options(&fusio_path, options).await {
        Ok(file) => Ok(file),
        Err(FusioError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            FileNotFoundSnafu { path: path.as_ref() }.fail()
        }
        err => err.context(FsSnafu { path: path.as_ref() }),
    }
}

/// Wrapper for [`AsyncFs::open_options`] with clearer errors when creating files.
pub async fn create_file<P: AsRef<Path>>(path: P) -> Result<<FsImpl as Fs>::File, FileError> {
    let fusio_path = FusioPath::new(path.as_ref())?;
    let options = OpenOptions::default().create(true).write(true).truncate(true);

    match FS.open_options(&fusio_path, options).await {
        Ok(file) => Ok(file),
        Err(FusioError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            AlreadyExistsSnafu { path: path.as_ref() }.fail()
        }
        Err(FusioError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            FileParentNotFoundSnafu { path: path.as_ref() }.fail()
        }
        err => err.context(FsSnafu { path: path.as_ref() }),
    }
}

/// Creates a file using [`create_file`] and its parent directories using [`create_dir_all`].
pub async fn create_file_and_dirs<P: AsRef<Path>>(path: P) -> Result<<FsImpl as Fs>::File, FileError> {
    let path_ref = path.as_ref();

    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).await?;
    }

    create_file(path_ref).await
}

/// Wrapper for [`async_fs::read`] with clearer errors.
pub async fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, FileError> {
    let mut file = open_file(path.as_ref()).await?;
    let (result, buf) = file.read_to_end_at(Vec::new(), 0).await;

    if let Err(FusioError::Io(err)) = result.as_ref() {
        if err.kind() == std::io::ErrorKind::OutOfMemory {
            return FileOutOfMemorySnafu { path: path.as_ref() }.fail();
        }
        if err.kind() == std::io::ErrorKind::NotFound {
            return FileNotFoundSnafu { path: path.as_ref() }.fail();
        }
    }

    result.context(FsSnafu { path: path.as_ref() })?;
    Ok(buf)
}

/// Wrapper for [`Fs::open_options`] with clearer errors when writing files.
pub async fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), FileError> {
    let fusio_path = FusioPath::new(path.as_ref())?;
    let options = OpenOptions::default().create(true).truncate(true).write(true);

    let mut file = match FS.open_options(&fusio_path, options).await {
        Ok(file) => file,
        Err(FusioError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return FileParentNotFoundSnafu { path: path.as_ref() }.fail();
        }
        Err(err) => return Err(err).context(FsSnafu { path: path.as_ref() }),
    };

    let buffer = contents.as_ref();
    let (result, _) = file.write_all(buffer).await;
    if let Err(FusioError::Io(err)) = result.as_ref() {
        if err.kind() == std::io::ErrorKind::OutOfMemory {
            return FileOutOfMemorySnafu { path: path.as_ref() }.fail();
        }
    }

    result.context(FsSnafu { path: path.as_ref() })?;
    file.flush().await.context(FsSnafu { path: path.as_ref() })?;
    file.close().await.context(FsSnafu { path: path.as_ref() })?;

    Ok(())
}

/// Wrapper for [`Fs::open_options`] with clearer errors.
pub async fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String, FileError> {
    let mut file = open_file(path.as_ref()).await?;
    let (result, buf) = file.read_to_end_at(Vec::new(), 0).await;

    if let Err(FusioError::Io(err)) = result.as_ref() {
        if err.kind() == std::io::ErrorKind::OutOfMemory {
            return FileOutOfMemorySnafu { path: path.as_ref() }.fail();
        }
        if err.kind() == std::io::ErrorKind::NotFound {
            return FileNotFoundSnafu { path: path.as_ref() }.fail();
        }
    }

    result.context(FsSnafu { path: path.as_ref() })?;
    Ok(String::from_utf8(buf).unwrap())
}

/// Wrapper for [`Fs::list`] with clearer errors.
pub async fn read_dir<P: AsRef<Path>>(path: P) -> Result<Vec<std::path::PathBuf>, FileError> {
    let fusio_path = FusioPath::new(path.as_ref())?;

    let stream = FS.list(&fusio_path).await.map_err(|err| match err {
        FusioError::Io(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
            DirNotFoundSnafu { path: path.as_ref() }.build()
        }
        FusioError::Io(io_err) if io_err.kind() == std::io::ErrorKind::OutOfMemory => {
            DirOutOfMemorySnafu { path: path.as_ref() }.build()
        }
        other => panic!("read_dir failed: {}", other),
    })?;

    futures::pin_mut!(stream);

    let mut entries = Vec::new();
    while let Some(next) = stream.next().await {
        match next {
            Ok(meta) => {
                let entry_path = std::path::PathBuf::from("/").join(meta.path.as_ref());
                entries.push(entry_path);
            }
            Err(error) => {
                return Err(error).context(FsSnafu { path: path.as_ref() });
            }
        }
    }

    Ok(entries)
}

/// Wrapper for [`AsyncFs::create_dir_all`] with clearer errors.
pub async fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<(), FileError> {
    let fusio_path = FusioPath::new(path.as_ref())?;
    FsImpl::create_dir_all(&fusio_path).await.context(FsSnafu { path: path.as_ref() })?;
    Ok(())
}

pub async fn read_yaml<R, T>(reader: &mut R) -> Result<T, SerdeYmlError>
where
    R: Read,
    T: DeserializeOwned,
{
    let (result, buf) = reader.read_to_end_at(Vec::new(), 0).await;
    match result {
        Ok(()) => serde_yml::from_slice(buf.as_slice()),
        Err(err) => panic!("read_yaml failed: {}", err),
    }
}

pub async fn write_yaml<W, T>(writer: &mut W, value: &T) -> Result<(), SerdeYmlError>
where
    W: Write,
    T: Serialize,
{
    let mut serialized = Vec::new();
    serde_yml::to_writer(&mut serialized, value)?;
    let (result, _) = writer.write_all(serialized).await;
    writer.flush().await.unwrap();
    writer.close().await.unwrap();
    match result {
        Ok(()) => Ok(()),
        Err(err) => panic!("write_yaml failed: {}", err),
    }
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
