//! `vitonomi-cli credential generate` — local password generator.
//! Pure-local; no hub round-trip.

use anyhow::anyhow;

use vitonomi_core::credentials::password_gen::{generate, ClassMask, GenSpec};

use crate::prompts::Prompts;

pub struct CredentialGenerateArgs {
    pub length: usize,
    pub strong: bool,
    pub exclude_ambiguous: bool,
}

pub async fn run<P: Prompts + ?Sized>(
    args: CredentialGenerateArgs,
    _prompts: &mut P,
) -> anyhow::Result<()> {
    let spec = if args.strong {
        let mut s = GenSpec::strong();
        s.exclude_ambiguous = args.exclude_ambiguous;
        if args.length > s.length {
            s.length = args.length;
        }
        s
    } else {
        GenSpec {
            length: args.length,
            classes: ClassMask::default(),
            exclude_ambiguous: args.exclude_ambiguous,
            min_per_class: 1,
        }
    };
    let pw = generate(&spec).map_err(|e| anyhow!("password generate: {e}"))?;
    println!("{pw}");
    Ok(())
}
