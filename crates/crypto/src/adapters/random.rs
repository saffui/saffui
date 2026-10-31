use saffui_core::ports::random::{Random, RandomUnavailable};

use super::SharedProvider;

/// The generator of the provider.
pub struct ProviderRandom {
    provider: SharedProvider,
}

impl ProviderRandom {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self { provider }
    }
}

impl Random for ProviderRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
        self.provider
            .rand()
            .fill(buffer)
            .map_err(|_| RandomUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::random::Random;

    use super::ProviderRandom;
    use crate::adapters::open_provider;

    #[test]
    fn two_draws_differ() {
        let random = ProviderRandom::new(open_provider().expect("a provider"));
        let (mut first, mut second) = ([0_u8; 32], [0_u8; 32]);

        random.fill(&mut first).expect("a draw");
        random.fill(&mut second).expect("a draw");

        assert_ne!(first, second);
        assert_ne!(first, [0_u8; 32]);
    }
}
