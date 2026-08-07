use pingora_memory_cache::CacheStatus as PingoraCacheStatus;
use pingora_memory_cache::MemoryCache as PingoraMemoryCache;
use std::{borrow::Borrow, hash::Hash, time::Duration};

#[derive(Debug, PartialEq, Eq)]
/// [CacheStatus] indicates the response type for a query.
pub enum CacheStatus {
    /// The key was found in the cache
    Hit,
    /// The key was not found.
    Miss,
    /// The key was found but it was expired.
    Expired,
    /// The key was not initially found but was found after awaiting a lock.
    LockHit,
    /// The returned value was expired but still returned. The [Duration] is
    /// how long it has been since its expiration time.
    Stale(Duration),
}

impl CacheStatus {
    /// Return the string representation for [CacheStatus].
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Expired => "expired",
            Self::LockHit => "lock_hit",
            Self::Stale(_) => "stale",
        }
    }

    /// Returns whether this status represents a cache hit.
    pub fn is_hit(&self) -> bool {
        match self {
            CacheStatus::Hit | CacheStatus::LockHit | CacheStatus::Stale(_) => true,
            CacheStatus::Miss | CacheStatus::Expired => false,
        }
    }

    /// Returns the stale duration if any
    pub fn stale(&self) -> Option<Duration> {
        match self {
            CacheStatus::Stale(time) => Some(*time),
            _ => None,
        }
    }
}

impl From<PingoraCacheStatus> for CacheStatus {
    fn from(status: PingoraCacheStatus) -> Self {
        match status {
            PingoraCacheStatus::Hit => Self::Hit,
            PingoraCacheStatus::Miss => Self::Miss,
            PingoraCacheStatus::Expired => Self::Expired,
            PingoraCacheStatus::LockHit => Self::LockHit,
            PingoraCacheStatus::Stale(duration) => Self::Stale(duration),
        }
    }
}

/// A high performant in-memory cache with S3-FIFO + TinyLFU
pub struct MemoryCache<K: Hash, T: Clone> {
    inner: PingoraMemoryCache<K, T>,
}

impl<K: Hash, T: Clone + Send + Sync + 'static> MemoryCache<K, T> {
    /// Create a new [MemoryCache] with the given size.
    pub fn new(size: usize) -> Self {
        MemoryCache { inner: PingoraMemoryCache::new(size) }
    }

    /// Fetch the key and return its value in addition to a [CacheStatus].
    #[inline]
    pub fn get<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, status) = self.inner.get(key);
        (value, status.into())
    }

    /// Fetch the key and return only its value as an [Option].
    #[inline]
    pub fn get_value<Q>(&self, key: &Q) -> Option<T>
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, _) = self.get(key);
        value
    }

    /// Similar to [Self::get], fetch the key and return its value in addition to a
    /// [CacheStatus] but also return the value even if it is expired. When the
    /// value is expired, the [Duration] of how long it has been stale will
    /// also be returned.
    #[inline]
    pub fn get_stale<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, status) = self.inner.get_stale(key);
        (value, status.into())
    }

    /// Insert a key and value pair with an optional TTL into the cache.
    ///
    /// An item with zero TTL of zero will not be inserted.
    #[inline]
    pub fn put<Q>(&self, key: &Q, value: T, ttl: Option<Duration>)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        if let Some(t) = ttl {
            if t.is_zero() {
                return;
            }
        }
        self.inner.put(key, value, ttl);
    }

    /// Remove a key from the cache if it exists.
    #[inline]
    pub fn remove<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        self.inner.remove(key);
    }

    /// This is equivalent to [MemoryCache::get] but for an arbitrary amount of keys.
    #[inline]
    pub fn multi_get<'a, I, Q>(&self, keys: I) -> Vec<(Option<T>, CacheStatus)>
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        for key in keys {
            resp.push(self.get(key));
        }
        resp
    }

    /// Same as [MemoryCache::multi_get] but returns the keys that are missing from the cache.
    #[inline]
    pub fn multi_get_with_miss<'a, I, Q>(&self, keys: I) -> (Vec<(Option<T>, CacheStatus)>, Vec<&'a Q>)
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        let mut missed = Vec::with_capacity(keys.size_hint().0 / 2);
        for key in keys {
            let (lookup, cache_status) = self.get(key);
            if lookup.is_none() {
                missed.push(key);
            }
            resp.push((lookup, cache_status));
        }
        (resp, missed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_status_as_str() {
        assert_eq!(CacheStatus::Hit.as_str(), "hit");
        assert_eq!(CacheStatus::Miss.as_str(), "miss");
        assert_eq!(CacheStatus::Expired.as_str(), "expired");
        assert_eq!(CacheStatus::LockHit.as_str(), "lock_hit");
        assert_eq!(CacheStatus::Stale(Duration::from_secs(5)).as_str(), "stale");
    }

    #[test]
    fn cache_status_is_hit() {
        assert!(CacheStatus::Hit.is_hit());
        assert!(CacheStatus::LockHit.is_hit());
        assert!(CacheStatus::Stale(Duration::from_secs(1)).is_hit());
        assert!(!CacheStatus::Miss.is_hit());
        assert!(!CacheStatus::Expired.is_hit());
    }

    #[test]
    fn cache_status_stale_returns_duration() {
        let d = Duration::from_secs(42);
        assert_eq!(CacheStatus::Stale(d).stale(), Some(d));
        assert_eq!(CacheStatus::Hit.stale(), None);
        assert_eq!(CacheStatus::Miss.stale(), None);
        assert_eq!(CacheStatus::Expired.stale(), None);
        assert_eq!(CacheStatus::LockHit.stale(), None);
    }

    #[test]
    fn cache_status_from_pingora() {
        assert_eq!(
            CacheStatus::from(PingoraCacheStatus::Hit),
            CacheStatus::Hit
        );
        assert_eq!(
            CacheStatus::from(PingoraCacheStatus::Miss),
            CacheStatus::Miss
        );
        assert_eq!(
            CacheStatus::from(PingoraCacheStatus::Expired),
            CacheStatus::Expired
        );
        assert_eq!(
            CacheStatus::from(PingoraCacheStatus::LockHit),
            CacheStatus::LockHit
        );
        let d = Duration::from_secs(3);
        assert_eq!(
            CacheStatus::from(PingoraCacheStatus::Stale(d)),
            CacheStatus::Stale(d)
        );
    }

    #[test]
    fn memory_cache_put_and_get() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"key", "value", Some(Duration::from_secs(60)));
        let (val, status) = c.get(&"key");
        assert_eq!(val, Some("value"));
        assert_eq!(status, CacheStatus::Hit);
    }

    #[test]
    fn memory_cache_get_miss() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        let (val, status) = c.get(&"missing");
        assert_eq!(val, None);
        assert_eq!(status, CacheStatus::Miss);
    }

    #[test]
    fn memory_cache_get_value() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_secs(60)));
        assert_eq!(c.get_value(&"k"), Some("v"));
        assert_eq!(c.get_value(&"missing"), None);
    }

    #[test]
    fn memory_cache_put_zero_ttl_not_inserted() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::ZERO));
        assert_eq!(c.get_value(&"k"), None);
    }

    #[test]
    fn memory_cache_remove() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_secs(60)));
        c.remove(&"k");
        assert_eq!(c.get_value(&"k"), None);
    }

    #[test]
    fn memory_cache_multi_get() {
        let c: MemoryCache<&str, i32> = MemoryCache::new(100);
        c.put(&"a", 1, Some(Duration::from_secs(60)));
        c.put(&"b", 2, Some(Duration::from_secs(60)));
        let results = c.multi_get(["a", "b", "c"].iter());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], (Some(1), CacheStatus::Hit));
        assert_eq!(results[1], (Some(2), CacheStatus::Hit));
        assert_eq!(results[2].0, None);
    }

    #[test]
    fn memory_cache_multi_get_with_miss() {
        let c: MemoryCache<&str, i32> = MemoryCache::new(100);
        c.put(&"a", 1, Some(Duration::from_secs(60)));
        let (results, missed) = c.multi_get_with_miss(["a", "b", "c"].iter());
        assert_eq!(results.len(), 3);
        assert_eq!(missed, vec![&"b", &"c"]);
    }

    #[test]
    fn memory_cache_get_stale_returns_expired_value() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(30));
        let (val, status) = c.get_stale(&"k");
        assert_eq!(val, Some("v"));
        assert!(matches!(status, CacheStatus::Stale(_)));
    }
}
