use lazy_hash::{
    Result,
    Secret,
};
fn main() -> Result<()> {
    let secret = Secret::generate_secret();
    println!("{}", secret);
    Ok(())
}
