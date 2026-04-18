use pelite::pe64::{Pe, PeFile};
use pelite::FileMap;

fn main() {
    let path = std::path::Path::new("testing.dll");
    let map = FileMap::open(path).expect("Failed to open file");
    let file = PeFile::from_bytes(map.as_ref()).expect("Failed to parse PE");
    let resources = file.resources().expect("Failed to get resources");
    let version_info = resources.version_info().expect("Failed to get version info");
    
    for &lang in version_info.translation() {
        version_info.strings(lang, |key, value| {
            println!("Key: {}, Value: {}", key, value);
        });
    }
}
