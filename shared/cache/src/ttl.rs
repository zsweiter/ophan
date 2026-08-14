use dashmap::DashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
}

impl<V> CacheEntry<V> {
    #[inline]
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// A lightweight, highly concurrent TTL-based cache built on top of `DashMap`.
///
/// It uses lazy eviction to clean up expired entries during normal read/write operations,
/// avoiding the need for background cleanup threads.
pub struct Cache<K, V> {
    cache: DashMap<K, CacheEntry<V>>,
    default_ttl: Duration,
    max_capacity: Option<usize>,

    len_count: AtomicUsize,
    near_expiry_threshold: Duration,
}

impl<K, V> Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Creates a new `Cache` with a default Time-To-Live duration.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
            max_capacity: None,
            len_count: AtomicUsize::new(0),
            near_expiry_threshold: Duration::from_secs(2),
        }
    }

    /// Sets a soft capacity limit. When exceeded, a manual purge of expired items can be triggered.
    pub fn with_capacity(default_ttl: Duration, capacity: usize) -> Self {
        Self {
            cache: DashMap::with_capacity(capacity),
            default_ttl,
            max_capacity: Some(capacity),
            len_count: AtomicUsize::new(0),
            near_expiry_threshold: Duration::from_secs(2),
        }
    }

    /// Inserts a key-value pair into the cache with the default TTL.
    pub fn put(&self, key: K, value: V, ttl: Option<Duration>) {
        self.ensure_capacity();

        let entry = CacheEntry {
            value,
            expires_at: Instant::now() + ttl.unwrap_or(self.default_ttl),
        };

        if self.cache.insert(key, entry).is_none() {
            self.len_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retrieves a cloned value from the cache if it exists and has not expired.
    /// Expired entries are lazily evicted on access.
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.cache.get(key) {
            let now = Instant::now();
            if entry.is_expired(now) {
                drop(entry);
                if self.cache.remove(key).is_some() {
                    self.len_count.fetch_sub(1, Ordering::Relaxed);
                }

                None
            } else {
                Some(entry.value.clone())
            }
        } else {
            None
        }
    }

    /// Atomically checks if a key exists and is valid. If it does not exist or has expired,
    /// it inserts the new key-value pair and returns `true`.
    ///
    /// Returns `false` if the key exists and is still valid (ideal for replay attack checks, rate limiting, or deduplication).
    pub fn set_nx(&self, key: K, value: V, ttl: Option<Duration>) -> bool {
        let now = Instant::now();
        let expires_at = now + ttl.unwrap_or(self.default_ttl);

        self.ensure_capacity();

        match self.cache.entry(key) {
            dashmap::Entry::Occupied(mut entry) => {
                if entry.get().is_expired(now) {
                    entry.insert(CacheEntry { value, expires_at });
                    true
                } else {
                    false
                }
            },
            dashmap::Entry::Vacant(entry) => {
                entry.insert(CacheEntry { value, expires_at });
                self.len_count.fetch_add(1, Ordering::Relaxed);
                true
            },
        }
    }

    /// Returns `true` if the cache contains a non-expired entry for the given key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Manually removes a key from the cache.
    pub fn remove(&self, key: &K) -> Option<V> {
        let value = self.cache.remove(key).map(|(_, entry)| entry.value);
        if value.is_some() {
            self.len_count.fetch_sub(1, Ordering::Relaxed);
        }

        value
    }

    #[inline]
    fn ensure_capacity(&self) {
        let Some(limit) = self.max_capacity else {
            return;
        };

        if self.len_count.load(Ordering::Relaxed) >= limit {
            let amount = usize::max(limit / 10, 16);

            self.evict_smart_conditional(amount);
        }
    }

    /// Iterates through all entries and purges the ones that have expired.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| !entry.is_expired(now));
        self.len_count.store(self.cache.len(), Ordering::Relaxed);
    }

    fn evict_smart_conditional(&self, sample_size: usize) {
        let now = Instant::now();

        let sample: Vec<(K, Instant)> = self
            .cache
            .iter()
            .take(sample_size)
            .map(|entry| (entry.key().clone(), entry.value().expires_at))
            .collect();

        if sample.is_empty() {
            return;
        }

        let mut keys_to_remove: Vec<K> = sample
            .iter()
            .filter(|(_, expires_at)| {
                let remaining = expires_at.saturating_duration_since(now);
                remaining == Duration::ZERO || remaining <= self.near_expiry_threshold
            })
            .map(|(key, _)| key.clone())
            .collect();

        if keys_to_remove.is_empty()
            && let Some((closest_key, _)) = sample.into_iter().min_by_key(|(_, expires_at)| *expires_at)
        {
            keys_to_remove.push(closest_key);
        }

        let mut removed_count = 0;
        for key in keys_to_remove {
            if self.cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.len_count.fetch_sub(removed_count, Ordering::Relaxed);
        }
    }

    /// Removes all elements from the cache.
    pub fn clear(&self) {
        self.cache.clear();
        self.len_count.store(0, Ordering::Relaxed);
    }

    /// Returns the total number of key-value pairs in the cache (including non-purged expired ones).
    pub fn len(&self) -> usize {
        self.len_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the cache contains no elements.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(default_ttl: Duration) -> Cache<String, String> {
        Cache::new(default_ttl)
    }

    #[test]
    fn insert_and_get() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        assert_eq!(c.get(&"a".into()), Some("1".into()));
    }

    #[test]
    fn get_missing_key() {
        let c = cache(Duration::from_secs(60));
        assert_eq!(c.get(&"missing".into()), None);
    }

    #[test]
    fn insert_overwrites_existing() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        c.put("a".into(), "2".into(), None);
        assert_eq!(c.get(&"a".into()), Some("2".into()));
    }

    #[test]
    fn insert_does_not_increase_len_on_overwrite() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        c.put("a".into(), "2".into(), None);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn default_ttl_expires() {
        let c = cache(Duration::from_millis(50));
        c.put("a".into(), "1".into(), None);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(c.get(&"a".into()), None);
    }

    #[test]
    fn custom_ttl_overrides_default() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), Some(Duration::from_millis(50)));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(c.get(&"a".into()), None);
    }

    #[test]
    fn long_custom_ttl() {
        let c = cache(Duration::from_millis(10));
        c.put("a".into(), "1".into(), Some(Duration::from_secs(60)));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(c.get(&"a".into()), Some("1".into()));
    }

    #[test]
    fn check_and_insert_new_key() {
        let c = cache(Duration::from_secs(60));
        assert!(c.set_nx("a".into(), "1".into(), None));
        assert_eq!(c.get(&"a".into()), Some("1".into()));
    }

    #[test]
    fn check_and_insert_existing_valid_key() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        assert!(!c.set_nx("a".into(), "2".into(), None));
        assert_eq!(c.get(&"a".into()), Some("1".into()));
    }

    #[test]
    fn check_and_insert_expired_key() {
        let c = cache(Duration::from_millis(50));
        c.put("a".into(), "1".into(), None);
        std::thread::sleep(Duration::from_millis(80));
        assert!(c.set_nx("a".into(), "2".into(), None));
        assert_eq!(c.get(&"a".into()), Some("2".into()));
    }

    #[test]
    fn contains_key() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        assert!(c.contains_key(&"a".into()));
        assert!(!c.contains_key(&"b".into()));
    }

    #[test]
    fn contains_key_expired() {
        let c = cache(Duration::from_millis(50));
        c.put("a".into(), "1".into(), None);
        std::thread::sleep(Duration::from_millis(80));
        assert!(!c.contains_key(&"a".into()));
    }

    #[test]
    fn remove_existing() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        assert_eq!(c.remove(&"a".into()), Some("1".into()));
        assert_eq!(c.get(&"a".into()), None);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn remove_missing() {
        let c: Cache<String, String> = cache(Duration::from_secs(60));
        assert_eq!(c.remove(&"a".into()), None);
    }

    #[test]
    fn clear() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), None);
        c.put("b".into(), "2".into(), None);
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn len_tracks_inserts_and_removes() {
        let c = cache(Duration::from_secs(60));
        assert_eq!(c.len(), 0);
        c.put("a".into(), "1".into(), None);
        c.put("b".into(), "2".into(), None);
        assert_eq!(c.len(), 2);
        c.remove(&"a".into());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn is_empty() {
        let c: Cache<String, String> = cache(Duration::from_secs(60));
        assert!(c.is_empty());
        c.put("a".into(), "1".into(), None);
        assert!(!c.is_empty());
    }

    #[test]
    fn purge_expired_removes_only_expired() {
        let c = cache(Duration::from_secs(60));
        c.put("a".into(), "1".into(), Some(Duration::from_millis(10)));
        c.put("b".into(), "2".into(), None);
        std::thread::sleep(Duration::from_millis(30));
        c.purge_expired();
        assert_eq!(c.get(&"a".into()), None);
        assert_eq!(c.get(&"b".into()), Some("2".into()));
    }

    #[test]
    fn with_capacity_creates_cache() {
        let c: Cache<String, String> = Cache::with_capacity(Duration::from_secs(60), 100);
        c.put("a".into(), "1".into(), None);
        assert_eq!(c.get(&"a".into()), Some("1".into()));
    }

    #[test]
    fn with_capacity_evicts_when_full() {
        let c: Cache<String, String> = Cache::with_capacity(Duration::from_secs(60), 4);
        for i in 0..4 {
            c.put(format!("{i}"), format!("{i}"), None);
        }
        c.put("overflow".into(), "x".into(), None);
        assert!(c.len() <= 4);
    }

    #[test]
    fn with_capacity_evicts_expired_first() {
        let c: Cache<String, String> = Cache::with_capacity(Duration::from_millis(30), 2);
        c.put("a".into(), "1".into(), None);
        c.put("b".into(), "2".into(), None);
        std::thread::sleep(Duration::from_millis(50));
        c.put("c".into(), "3".into(), None);
        assert!(c.len() <= 2);
    }
}
