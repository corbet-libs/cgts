//! CI-only probe: succeeds in debug and must fail in release.
fn main() {
    let _ = cgts::gates::development::descriptor();
}
