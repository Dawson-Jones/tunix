use crate::error::{Error, Result};

pub(crate) fn write_if_name(name: &str, dst: &mut [libc::c_char]) -> Result<()> {
    if name.len() >= dst.len() {
        return Err(Error::NameTooLong);
    }

    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidName);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            dst.as_mut_ptr(),
            name.len(),
        )
    };

    Ok(())
}
