use std::{borrow::Cow, mem::size_of};

use anyhow::Result;
use ds_rom::{
    crypto::{
        dsprot::{
            DsProtDecryptResult, DsProtFunction, DsProtRelocation, DsProtState, DsProtVersionNumber, EncryptedRange,
            EncryptionType, FunctionTable,
        },
        hmac_sha1::HmacSha1,
        modcrypt::Modcrypt,
    },
    rom::{
        Arm7, Arm7Offsets, Arm9, Arm9Offsets, Arm9Options, Arm9WithTcmsOptions, Banner, DsiArea, DsiProgram,
        DsiProgramOffsets, File, FileSystem, Header, Logo, Overlay, OverlayInfo, OverlayOptions, OverlayTable, Rom, RomConfig,
        RomConfigAlignment, RomConfigAutoload, RomConfigPaddingValues, raw,
    },
};

const ARM9_BASE: u32 = 0x0200_0000;
const BUILD_INFO_OFFSET: u32 = 0x40;

// Store the source as words so borrowed BuildInfo references are correctly aligned.
fn arm9_words() -> Vec<u32> {
    let mut words = vec![0; 0x900 / size_of::<u32>()];
    let data: &mut [u8] = bytemuck::cast_slice_mut(&mut words);
    data[..8].copy_from_slice(&[0xff, 0xde, 0xff, 0xe7, 0xff, 0xde, 0xff, 0xe7]);
    let info_end = BUILD_INFO_OFFSET as usize + size_of::<raw::BuildInfo>();
    data[info_end - 8..info_end - 4].copy_from_slice(&raw::NITROCODE.to_le_bytes());
    data[info_end - 4..info_end].copy_from_slice(&raw::NITROCODE.swap_bytes().to_le_bytes());
    data[0x100..0x110].copy_from_slice(b"synthetic arm9!!");
    let end_address = ARM9_BASE + data.len() as u32;
    let info = raw::BuildInfo::borrow_from_slice_mut(&mut data[BUILD_INFO_OFFSET as usize..]).unwrap();
    info.autoload_blocks = end_address;
    info.autoload_infos_start = end_address;
    info.autoload_infos_end = end_address;
    info.bss_start = end_address;
    info.bss_end = end_address + 0x80;
    info.sdk_version = 0x0402_7531;
    words
}

fn arm9_offsets() -> Arm9Offsets {
    Arm9Offsets {
        base_address: ARM9_BASE,
        entry_function: ARM9_BASE + 0x100,
        build_info: BUILD_INFO_OFFSET,
        autoload_callback: ARM9_BASE + 0x120,
        overlay_signatures: 0,
    }
}

fn dsprot_result() -> DsProtDecryptResult {
    DsProtDecryptResult {
        version: DsProtVersionNumber::V1_25,
        encrypted_ranges: vec![EncryptedRange {
            start_address: ARM9_BASE + 0x100,
            end_address: ARM9_BASE + 0x140,
            seed_key: 0x1234_5678,
        }],
        bss_variable: Some(ARM9_BASE + 0x900),
        functions: vec![DsProtFunction {
            address: ARM9_BASE + 0x180,
            size: 0x20,
            pool_size: Some(0x10),
            encryption: EncryptionType::Unkeyed,
            function_table: Some(FunctionTable { length: 2, has_garbage: true, has_overwrite: true }),
        }],
        relocations: vec![DsProtRelocation { from_address: ARM9_BASE + 0x1a0, to_address: ARM9_BASE + 0x180, addend: 0x30 }],
    }
}

fn overlay<'a>(data: &'a [u8], dsprot_state: DsProtState) -> Result<Overlay<'a>> {
    Ok(Overlay::new(data, OverlayOptions {
        originally_compressed: false,
        originally_signed: true,
        info: OverlayInfo {
            id: 0,
            base_address: ARM9_BASE,
            code_size: data.len() as u32,
            bss_size: 0x40,
            ctor_start: ARM9_BASE + 4,
            ctor_end: ARM9_BASE + 8,
            file_id: 0,
            compressed: false,
        },
        dsprot_state,
    })?)
}

fn dsi_offsets(base_address: u32, modcrypt_size: u32) -> DsiProgramOffsets {
    DsiProgramOffsets { entry_function: base_address + 4, base_address, build_info_offset: 8, modcrypt_size }
}

fn assert_dsi_offsets(actual: &DsiProgramOffsets, expected: DsiProgramOffsets) {
    assert_eq!(actual.entry_function, expected.entry_function);
    assert_eq!(actual.base_address, expected.base_address);
    assert_eq!(actual.build_info_offset, expected.build_info_offset);
    assert_eq!(actual.modcrypt_size, expected.modcrypt_size);
}

#[test]
fn borrowed_arm9_into_owned_outlives_source_and_preserves_footer() -> Result<()> {
    for has_footer in [false, true] {
        let expected_data;
        let mut owned: Arm9<'static> = {
            let mut source = arm9_words();
            expected_data = bytemuck::cast_slice::<_, u8>(&source).to_vec();
            let arm9 = Arm9::new(bytemuck::cast_slice::<_, u8>(&source), arm9_offsets(), Arm9Options { has_footer })?;
            let expected = arm9.clone();
            let owned = arm9.into_owned();
            assert!(owned == expected);
            drop(expected);
            source.fill(0);
            owned
        };
        assert_eq!(owned.full_data(), expected_data);
        assert_eq!(owned.has_footer(), has_footer);
        assert!(*owned.offsets() == arm9_offsets());
        assert_eq!(owned.bss()?, ARM9_BASE + 0x900..ARM9_BASE + 0x980);
        assert!(!owned.is_compressed()?);
        owned.build_info_mut()?.sdk_version += 1;
        assert_eq!(owned.build_info()?.sdk_version, 0x0402_7532);
    }
    Ok(())
}

#[test]
fn arm9_into_owned_preserves_dsprot_and_original_states() -> Result<()> {
    for state in [DsProtState::Encrypted(dsprot_result()), DsProtState::Unencrypted(dsprot_result())] {
        let arm9 = Arm9::with_autoloads(
            bytemuck::cast_slice::<_, u8>(&arm9_words()).to_vec(),
            &[],
            arm9_offsets(),
            Arm9WithTcmsOptions {
                originally_compressed: true,
                originally_encrypted: true,
                dsprot_state: state.clone(),
                has_footer: true,
            },
        )?;
        let expected = arm9.clone();
        let owned: Arm9<'static> = arm9.into_owned();
        assert!(owned == expected);
        assert_eq!(owned.dsprot_state(), &state);
        assert!(owned.originally_compressed());
        assert!(owned.originally_encrypted());
        assert!(owned.has_footer());
    }
    Ok(())
}

#[test]
fn borrowed_overlay_into_owned_retains_signature_and_dsprot() -> Result<()> {
    let key = HmacSha1::new([0x5a; 64]);
    for state in [DsProtState::Encrypted(dsprot_result()), DsProtState::Unencrypted(dsprot_result())] {
        let owned: Overlay<'static> = {
            let source = b"synthetic signed overlay".to_vec();
            let mut overlay = overlay(&source, state.clone())?;
            overlay.sign(&key)?;
            let expected = overlay.clone();
            let owned = overlay.into_owned();
            assert!(owned == expected);
            owned
        };
        assert_eq!(owned.full_data(), b"synthetic signed overlay");
        assert!(owned.originally_signed());
        assert!(owned.is_signed());
        assert_eq!(owned.dsprot_state(), &state);
        assert!(owned.verify_signature(&key)?);
        assert!(!owned.verify_signature(&HmacSha1::new([0x6b; 64]))?);
        assert!(owned.build().flags.is_signed());
    }
    Ok(())
}

#[test]
fn borrowed_dsi_programs_into_owned_retain_layout_and_modcrypt_behavior() {
    let expected_data = b"synthetic DSi program data";
    let offsets = dsi_offsets(0x02e0_0000, 12);
    let mut program: DsiProgram<'static> = {
        let source = expected_data.to_vec();
        DsiProgram::new(source.as_slice(), offsets).into_owned()
    };
    assert_dsi_offsets(program.offsets(), offsets);
    assert_eq!(program.full_data(), expected_data);
    assert!(program.is_modcrypted());
    let modcrypt = Modcrypt::new([0x42; 16]);
    program.apply_modcrypt(&modcrypt, [0x17; 16]);
    assert_ne!(&program.full_data()[..12], &expected_data[..12]);
    assert_eq!(&program.full_data()[12..], &expected_data[12..]);
    program.apply_modcrypt(&modcrypt, [0x17; 16]);
    assert_eq!(program.full_data(), expected_data);

    let area: DsiArea<'static> = {
        let arm9i = b"ARM9i program".to_vec();
        let arm7i = b"ARM7i program".to_vec();
        DsiArea {
            arm9i: DsiProgram::new(arm9i.as_slice(), offsets),
            arm7i: DsiProgram::new(arm7i.as_slice(), dsi_offsets(0x02f0_0000, 0)),
            region_padding: vec![0xff, 0x12, 0x34, 0xff].into_boxed_slice(),
        }
        .into_owned()
    };
    assert_eq!(area.arm9i.full_data(), b"ARM9i program");
    assert_eq!(area.arm7i.full_data(), b"ARM7i program");
    assert_dsi_offsets(area.arm9i.offsets(), offsets);
    assert_dsi_offsets(area.arm7i.offsets(), dsi_offsets(0x02f0_0000, 0));
    assert!(!area.arm7i.is_modcrypted());
    assert_eq!(area.region_padding.as_ref(), [0xff, 0x12, 0x34, 0xff]);
}

fn rom_config() -> RomConfig {
    RomConfig {
        header: "header.yaml".into(),
        header_logo: "logo.png".into(),
        arm9_bin: "arm9.bin".into(),
        arm9_config: "arm9.yaml".into(),
        arm7_bin: "arm7.bin".into(),
        arm7_config: "arm7.yaml".into(),
        itcm: RomConfigAutoload { bin: "itcm.bin".into(), config: "itcm.yaml".into() },
        dtcm: RomConfigAutoload { bin: "dtcm.bin".into(), config: "dtcm.yaml".into() },
        unknown_autoloads: vec![],
        arm9_overlays: Some("overlays.yaml".into()),
        arm7_overlays: None,
        banner: "banner.yaml".into(),
        files_dir: "files".into(),
        path_order: "path_order.txt".into(),
        arm9_hmac_sha1_key: Some("hmac.bin".into()),
        multiboot_signature: Some("multiboot.yaml".into()),
        dsi: None,
        alignment: RomConfigAlignment {
            arm9: 0x200,
            arm9_overlay_table: 4,
            arm9_overlay: 4,
            arm7: 0x200,
            arm7_overlay_table: 4,
            arm7_overlay: 4,
            file_name_table: 4,
            file_allocation_table: 4,
            banner: 0x200,
            file_image_block: 0x200,
            file: 4,
        },
        padding: RomConfigPaddingValues {
            arm9: 0xff,
            arm9_overlay_table: 0xff,
            arm9_overlays: 0xff,
            arm7: 0xff,
            arm7_overlay_table: 0xff,
            arm7_overlays: 0xff,
            fnt: 0xff,
            fat: 0xff,
            banner: 0xff,
            file_image: 0xff,
            rom: 0xff,
        },
    }
}

#[test]
fn borrowed_rom_into_owned_retains_new_fields_and_public_filesystem() -> Result<()> {
    let expected_hmac = HmacSha1::new([0x73; 64]).compute(b"retained key");
    let mut signature_bytes = vec![0x42; size_of::<raw::MultibootSignature>()];
    signature_bytes[..4].copy_from_slice(&raw::MULTIBOOT_SIGNATURE_MAGIC.to_le_bytes());
    let signature_len = signature_bytes.len();
    signature_bytes[signature_len - 4..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let owned: Rom<'static> = {
        let arm9 = arm9_words();
        let arm7 = b"synthetic ARM7".to_vec();
        let overlay_data = b"synthetic overlay".to_vec();
        let file_data = b"synthetic file contents".to_vec();
        let arm9i = b"synthetic ARM9i".to_vec();
        let arm7i = b"synthetic ARM7i".to_vec();
        let hmac_sha1 = HmacSha1::new([0x73; 64]);
        let mut signed_overlay = overlay(&overlay_data, DsProtState::Unencrypted(dsprot_result()))?;
        signed_overlay.sign(&hmac_sha1)?;
        let mut arm9_overlay_table = OverlayTable::new(vec![signed_overlay]);
        arm9_overlay_table.sign(&hmac_sha1);
        let mut files = FileSystem::new(1);
        files.files.push(File {
            id: 1,
            name: "asset.bin".into(),
            original_offset: 0x4000,
            contents: Cow::Borrowed(&file_data),
        });
        files.dirs[0].children.push(1);
        files.next_file_id = 2;
        Rom {
            header: Header::default(),
            header_logo: Logo::default(),
            arm9: Arm9::new(bytemuck::cast_slice::<_, u8>(&arm9), arm9_offsets(), Arm9Options { has_footer: true })?,
            arm9_overlay_table,
            arm7: Arm7::new(arm7.as_slice(), Arm7Offsets {
                base_address: 0x0380_0000,
                entry_function: 0x0380_0004,
                build_info: 0,
                autoload_callback: 0,
            }),
            arm7_overlay_table: OverlayTable::default(),
            banner: Banner::default(),
            files,
            multiboot_signature: Some(raw::MultibootSignature::from_slice(&signature_bytes)?),
            dsi: Some(DsiArea {
                arm9i: DsiProgram::new(arm9i.as_slice(), dsi_offsets(0x02e0_0000, 8)),
                arm7i: DsiProgram::new(arm7i.as_slice(), dsi_offsets(0x02f0_0000, 4)),
                region_padding: vec![0x01, 0xff, 0x10].into_boxed_slice(),
            }),
            hmac_sha1: Some(hmac_sha1),
            path_order: vec!["asset.bin".into()],
            config: rom_config(),
        }
        .into_owned()
    };

    assert_eq!(owned.arm9.full_data(), bytemuck::cast_slice::<_, u8>(&arm9_words()));
    assert!(owned.arm9.has_footer());
    assert_eq!(owned.arm7.full_data(), b"synthetic ARM7");
    assert_eq!(owned.files.find_path("asset.bin"), Some(1));
    assert_eq!(owned.files.file(1).contents(), b"synthetic file contents");
    assert_eq!(owned.files.files[0].original_offset, 0x4000);
    assert_eq!(owned.files.num_overlays, 1);
    assert_eq!(owned.files.next_file_id, 2);
    assert_eq!(owned.path_order, ["asset.bin"]);
    let key = owned.hmac_sha1.as_ref().unwrap();
    assert_eq!(key.compute(b"retained key"), expected_hmac);
    assert!(owned.arm9_overlay_table.verify_signature(key));
    assert!(owned.arm9_overlays()[0].verify_signature(key)?);
    assert_eq!(owned.arm9_overlays()[0].dsprot_state(), &DsProtState::Unencrypted(dsprot_result()));
    assert_eq!(bytemuck::bytes_of(owned.multiboot_signature().unwrap()), signature_bytes);
    assert_eq!(owned.multiboot_signature().unwrap().key_seed(), 0x1234_5678);
    let dsi = owned.dsi.as_ref().unwrap();
    assert_eq!(dsi.arm9i.full_data(), b"synthetic ARM9i");
    assert_eq!(dsi.arm7i.full_data(), b"synthetic ARM7i");
    assert_dsi_offsets(dsi.arm9i.offsets(), dsi_offsets(0x02e0_0000, 8));
    assert_dsi_offsets(dsi.arm7i.offsets(), dsi_offsets(0x02f0_0000, 4));
    assert_eq!(dsi.region_padding.as_ref(), [0x01, 0xff, 0x10]);
    assert_eq!(owned.config.padding.rom, 0xff);
    Ok(())
}
