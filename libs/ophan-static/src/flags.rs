#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    pub const LISTING: Self = Self(0b0000_0000_0000_0001);
    pub const DOTFILES: Self = Self(0b0000_0000_0000_0010);

    pub const SERVER_TOKENS: Self = Self(0b0000_0000_0000_0100);
    pub const X_FRAME_OPTS: Self = Self(0b0000_0000_0000_1000);
    pub const X_CONTENT_TYPE: Self = Self(0b0000_0000_0001_0000);
    pub const HSTS: Self = Self(0b0000_0000_0010_0000);
    pub const BLOCK_SYMLINKS: Self = Self(0b0000_0000_0100_0000);

    #[inline(always)]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline(always)]
    pub const fn bits(&self) -> u16 {
        self.0
    }

    pub const fn secure() -> Self {
        Self(Flags::BLOCK_SYMLINKS.bits() | Flags::DOTFILES.bits() | Flags::LISTING.bits())
    }

    #[inline(always)]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline(always)]
    pub const fn intersects(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    #[inline(always)]
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    #[inline(always)]
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl std::ops::BitOr for Flags {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
